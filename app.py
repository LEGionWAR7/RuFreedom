#!/usr/bin/env python3
"""
RuFreedom — графическая оболочка на pywebview.

Интерфейс — это HTML/CSS/JS в web/index.html, а вся логика обхода DPI остаётся
на Python (dpi/*). JS дёргает методы класса Api через window.pywebview.api, а
раз в секунду опрашивает get_state() и перерисовывает дашборд.

Запуск (от администратора — нужен WinDivert):
    python app.py
"""

from __future__ import annotations

import collections
import ctypes
import json
import os
import pathlib
import socket
import ssl
import sys
import threading
import time
import webbrowser

import webview

from dpi import (anticheat, autotune, config as config_mod, diagnose, services,
                 settings_store, tgbridge, tgproxy)
from dpi import autostart, conflicts, protocols, tempclean, update, voicecheck
from dpi.config import Config, Profile
from dpi.engine import Engine

try:
    import pystray
    from PIL import Image
except Exception:  # трей не обязателен
    pystray = None
    Image = None

STRATEGIES = set(config_mod.STRATEGIES)
QUIC_MODES = set(config_mod.QUIC_MODES)
FOOLINGS = set(config_mod.FOOLINGS)
SPLITS = set(config_mod.SPLITS)

# как часто сторож проверяет, не отвалился ли сервис
WATCH_PERIOD = 300.0
# сколько проверок подряд должно провалиться, прежде чем перепобирать
WATCH_STRIKES = 2
# не чаще одного авто-перепобора на группу в час
WATCH_COOLDOWN = 3600.0
# Сколько прошедших комбинаций собираем на группу, прежде чем выбирать
# лучшую. Один -- это «первый попавшийся», а он не обязательно лучший.
# Таймаут одного рукопожатия.
#
# Замерено на живой сети: до открытого хоста рукопожатие проходит за
# 0.15-1.3 с, а заблокированный НИКОГДА не отвечает отказом — он молчит до
# упора. Значит таймаут это и есть цена одной неудачной проверки, а неудачных
# в переборе подавляющее большинство.
#
# 3 секунды -- не «двойной запас», а осознанный компромисс. Замер снят БЕЗ
# обхода; с включённым десинком рукопожатие может стать чуть медленнее
# (переупорядоченные сегменты сервер иногда ждёт). Срезать до 2 с было бы
# соблазнительно, но ценой изредка забракованной рабочей стратегии -- а
# подтверждения она уже не увидит, потому что до него не дойдёт.
# Сколько живут имена, подсмотренные в трафике. Имена раздающих серверов
# YouTube и голосовых серверов Discord выдаются под сессию, и через несколько
# часов они уже ничьи. Разрешаться по DNS они при этом продолжают
# (*.googlevideo.com), поэтому единственная надёжная проверка — возраст.
SEEN_HOSTS_TTL = 6 * 3600

SCAN_TIMEOUT = 3.0
# Ниже этого не опускаемся, даже если сеть очень быстрая: обход добавляет
# переупорядоченные сегменты, и сервер иногда ждёт лишний круг.
SCAN_TIMEOUT_MIN = 1.2
# Во сколько раз ждём дольше, чем занимает заведомо успешное рукопожатие.
SCAN_MARGIN = 6
# Сколько проверенных комбинаций перепроверить не спеша, если группа не нашла
# вообще ничего. Только начало списка: там лежат проверенные временем связки,
# и если уж где-то мы поторопились, то именно там это стоит исправить.
SECOND_PASS = 20
# Что стоит одна проверка сверх ожидания ответа: подмена профиля и разбор.
# Раньше сюда входили ещё и открытие с закрытием драйвера — теперь движок
# на весь перебор один.
SWEEP_OVERHEAD = 0.25
# Там, где решается судьба стратегии (подтверждение и финал), спешить нельзя:
# лишняя секунда стоит дёшево, ошибочно забракованный победитель — дорого.
CHECK_TIMEOUT = 4.0

FINALISTS = 3
# Сколько комбинаций проверяем ПОСЛЕ первой удачной, если трёх так и не
# набралось. Без этого потолка группа, которой подходит ровно одна стратегия,
# заставляла перебрать весь список из 285 штук — минут сорок вместо минуты.
EXTRA_SCAN = 12


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def relaunch_as_admin() -> None:
    # для собранного exe перезапускаем сам exe, для скрипта — python со скриптом
    if getattr(sys, "frozen", False):
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, None, None, 1)
    else:
        script = os.path.abspath(__file__)
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}"', None, 1)


def _client_hello(host: str) -> bytes:
    """Настоящий ClientHello для имени — без единого пакета в сеть.

    Нужен, чтобы посчитать точки разреза заранее и понять, какие комбинации
    на самом деле неразличимы.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        inb, outb = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(inb, outb, server_hostname=host)
        try:
            obj.do_handshake()
        except Exception:                             # noqa: BLE001
            pass
        return outb.read()
    except Exception:                                 # noqa: BLE001
        return b""


def res_base() -> str:
    """Папка с ресурсами: _MEIPASS в собранном exe, иначе рядом со скриптом."""
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


class Sweep:
    """Один движок WinDivert на весь перебор вместо перезапуска на кандидата.

    Раньше каждая проверка поднимала и гасила драйвер заново: открыть, дождаться
    готовности, поспать, померить, закрыть, дождаться потока, поспать. На
    двухстах кандидатах это складывается в минуты чистых накладных расходов —
    и заодно двести раз дёргает драйвер, который от этого не становится
    здоровее.

    Держать движок открытым можно, потому что от стратегии зависит только то,
    ЧТО он делает с пакетом: профиль читается заново на каждом пакете
    (`cfg.profile_for`). Строка фильтра, диапазоны UDP и режим QUIC считаются
    один раз при запуске и от кандидата не зависят — они берутся из настроек,
    общих для всего перебора. Значит достаточно подменить профили.

    Список ХОСТОВ тоже фиксируется при запуске, поэтому он задаётся сразу
    самым широким: все группы перебора плюс подсмотренные имена.
    """

    def __init__(self, groups, quic_mode: str, cover=None, logger=None):
        self.groups = list(groups)
        self._log = logger or (lambda *_: None)
        cfg = Config()
        cfg.quic_mode = quic_mode
        cfg.host_groups = {host: gid
                           for gid, host in autotune.probe_targets(self.groups)}
        for gid, hosts in (cover or {}).items():
            if gid in self.groups:
                for host in hosts:
                    cfg.host_groups.setdefault(host, gid)
        cfg.hosts = set(cfg.host_groups)
        cfg.profiles = {}
        self.cfg = cfg
        self.engine = None
        self.thread = None
        self.error = ""

    @property
    def hosts(self):
        return list(self.cfg.host_groups)

    def start(self) -> bool:
        """Поднять движок. False — драйвер не открылся, причина в .error."""
        self.stop()
        eng = Engine(self.cfg, logger=lambda *_: None)
        th = threading.Thread(target=eng.run, daemon=True, name="rz-sweep")
        th.start()
        eng.ready.wait(timeout=5)         # взводится и при успехе, и при провале
        if not eng.running:
            self.error = eng.error or "причина неизвестна"
            self.engine, self.thread = None, None
            return False
        self.engine, self.thread = eng, th
        self.error = ""
        return True

    def alive(self) -> bool:
        eng = self.engine
        return bool(eng is not None and eng.running)

    def use(self, profile) -> None:
        """Поставить стратегию всем группам перебора."""
        self.cfg.profiles = {gid: profile for gid in self.groups}

    def stop(self) -> None:
        eng, th = self.engine, self.thread
        self.engine, self.thread = None, None
        if eng is not None:
            try:
                eng.stop()
            except Exception:                         # noqa: BLE001
                pass
        if th is not None:
            th.join(timeout=4)


class Api:
    """Мост между HTML-интерфейсом и движком обхода."""

    def __init__(self) -> None:
        self.s = self._normalize(settings_store.load())
        self.engine: Engine | None = None
        self.thread: threading.Thread | None = None
        self.log: collections.deque[str] = collections.deque(maxlen=400)
        self.auto = {"running": False, "progress": 0.0, "status": "", "best": None}
        self._auto_thread: threading.Thread | None = None
        # {группа: вердикт диагностики} — чем именно закрыт сервис
        self.diag: dict = dict(self.s.get("diag") or {})
        self.diag_running = False
        # античит: кто найден и не мы ли сами поставили обход на паузу
        self.ac_found: list = []
        self.ac_paused = False
        # локальный SOCKS5 для Telegram: его блокировку по IP обход не решает
        self.voice: dict = {}
        self.tg_proxy: dict | None = None
        self.tg_scan: dict | None = None
        self.tg_searching = False
        # встроенный мост: свой SOCKS5, уводящий Telegram в WebSocket
        self.bridge: tgbridge.TgBridge | None = None
        self.bridge_scan = {"running": False, "net": "", "step": 0,
                            "total": 0, "entries": list(self.s.get("tg_entries") or [])}
        self._bridge_stop = threading.Event()
        # Один замок на весь жизненный цикл: методы зовут и поток JS-моста, и
        # поток трея, и фоновые воркеры — без него они наступают друг на друга.
        self._lock = threading.RLock()
        # idle -> starting -> running -> stopping -> idle
        self.state = "idle"
        # поколение автоподбора: отставший воркер не должен трогать чужой запуск
        self._auto_gen = 0
        # Отмена подбора. Отдельный флаг, а не смена поколения: смена
        # поколения сбивает уборку за воркером, и «идёт подбор» залипло бы.
        self._auto_stop = threading.Event()
        # сколько строк лога всего было — клиент по нему понимает, что нового
        self._log_seq = 0
        # сторож: сколько проверок подряд провалила группа и когда её последний
        # раз перепобирали
        # что известно про обновления (заполняется в фоне, не на старте)
        self.upd: dict = {"current": update.VERSION, "latest": "", "newer": False,
                          "required": False, "url": update.RELEASES_URL, "notes": "",
                          "error": "", "checking": False, "asset": "", "size": 0,
                          "sha256": ""}
        # ход самой установки: скачивание -> подмена -> перезапуск
        self.updjob: dict = {"running": False, "stage": "", "done": 0,
                             "total": 0, "error": ""}
        self.upd_later = False        # человек нажал «Позже» в этом запуске
        # Кто ещё лезет в тот же трафик. Обновляется сторожем раз в пять
        # секунд — процессы приходят и уходят, разовой проверки мало.
        self.conflicts: list = []
        self._watch_strikes: dict = {}
        self._watch_last: dict = {}
        self._watch_at = time.monotonic()
        self._watch_stop = threading.Event()
        threading.Thread(target=self._watch_worker, daemon=True,
                         name="rz-watch").start()
        self._logput("[*] RuFreedom запущен." if is_admin()
                     else "[!] Запущено без прав администратора — включи «От админа».")

    # -- настройки ---------------------------------------------------------
    @staticmethod
    def _normalize(s: dict) -> dict:
        s = dict(s)
        if s.get("strategy") not in STRATEGIES:
            s["strategy"] = "multisplit"
        if s.get("quic_mode") not in QUIC_MODES:
            s["quic_mode"] = "drop"
        if s.get("fooling") not in FOOLINGS:
            s["fooling"] = "none"
        if s.get("split_mode") not in SPLITS:
            s["split_mode"] = "pos1"
        for key, lo, hi, dflt in (("fake_ttl", 1, 64, 4), ("fake_count", 1, 8, 2),
                                  ("seg_count", 2, 6, 2), ("seqovl", 0, 1400, 568)):
            try:
                s[key] = max(lo, min(hi, int(s.get(key, dflt))))
            except (TypeError, ValueError):
                s[key] = dflt
        s["all_traffic"] = bool(s.get("all_traffic", False))
        s["voice_fake"] = bool(s.get("voice_fake", True))
        s["voice_ttl"] = max(0, min(64, int(s.get("voice_ttl", 0) or 0)))
        s["voice_repeats"] = max(1, min(16, int(s.get("voice_repeats", 6) or 6)))
        s["watchdog"] = bool(s.get("watchdog", True))
        s["pause_on_anticheat"] = bool(s.get("pause_on_anticheat", False))
        ent = s.get("tg_entries")
        s["tg_entries"] = ([e for e in ent if isinstance(e, dict) and e.get("ip")]
                           if isinstance(ent, list) else [])
        # прошлый диагноз: чтобы при следующем запуске сразу знать, что
        # трогать, а что нет, и не ломать рабочие сайты до первой проверки
        d = s.get("diag")
        s["diag"] = ({k: v for k, v in d.items() if k in services.GROUPS}
                   if isinstance(d, dict) else {})
        # Группы, которые хоть раз видели заблокированными. Блокировка у
        # провайдера мигает: YouTube может на одной проверке ответить, а на
        # следующей нет. Без этой памяти он вылетал из обхода целиком.
        seen = s.get("blocked_seen")
        s["blocked_seen"] = ([g for g in seen if g in services.GROUPS]
                             if isinstance(seen, list) else [])
        streak = s.get("ok_streak")
        s["ok_streak"] = ({k: int(v) for k, v in streak.items()
                           if k in services.GROUPS}
                          if isinstance(streak, dict) else {})

        # Группы. Если ключа ещё нет — переносим старые категории, чтобы у тех,
        # кто обновился, галочки остались на месте.
        groups = s.get("groups")
        if not isinstance(groups, dict) or not groups:
            groups = services.migrate_categories(s.get("categories") or {})
        s["groups"] = {g: bool(groups.get(g, True)) for g in services.GROUPS}
        # Ещё релиз пишем и старый ключ: откат на прошлую сборку не должен
        # обнулить пользователю настройки.
        s["categories"] = services.to_legacy_categories(s["groups"])

        # Профили. settings_store.load() делает ПЛОСКИЙ dict.update, вложенные
        # словари он не сливает — поэтому нормализуем каждый профиль здесь.
        raw = s.get("profiles")
        profiles = {}
        if isinstance(raw, dict):
            for gid, body in raw.items():
                if gid in services.GROUPS:
                    profiles[gid] = Profile.from_dict(body).to_dict()
        s["profiles"] = profiles
        return s

    # сколько подряд «открывается» нужно, чтобы забыть про блокировку
    OK_TO_FORGET = 3

    def _remember_blocked(self, verdicts: dict) -> None:
        """Помнить, что группу видели заблокированной.

        Блокировка мигает: тот же YouTube на одной проверке отвечает, на
        следующей нет. Если верить последнему замеру, обход то включается, то
        выключается — со стороны это и есть «работает через раз». Поэтому
        группа остаётся в обходе, пока не отчитается открытой несколько
        проверок подряд.
        """
        seen = set(self.s.get("blocked_seen") or ())
        streak = dict(self.s.get("ok_streak") or {})
        for gid, v in verdicts.items():
            if v in ("sni", "unknown"):
                seen.add(gid)
                streak[gid] = 0
            elif v == "ok":
                streak[gid] = streak.get(gid, 0) + 1
                if streak[gid] >= self.OK_TO_FORGET and gid in seen:
                    seen.discard(gid)
                    self._logput(f"[*] {services.title(gid)} открывается "
                                 f"{streak[gid]} проверки подряд — убираю из обхода.")
            else:
                streak[gid] = 0
        self.s["blocked_seen"] = sorted(seen)
        self.s["ok_streak"] = streak

    def _profile_of(self, gid: str) -> Profile:
        """Профиль группы: свой, если подобран, иначе общий по умолчанию."""
        body = self.s["profiles"].get(gid)
        prof = Profile.from_dict(body) if body else self._default_profile()
        if services.udp_range(gid):
            prof.udp_fake = bool(self.s["voice_fake"])
            # Голосовые настройки живут отдельно от подобранного профиля:
            # подбор их не проверяет и проверить не может — рукопожатия к
            # голосовому серверу Discord со стороны не сделать.
            prof.voice_ttl = int(self.s["voice_ttl"])
            prof.voice_repeats = int(self.s["voice_repeats"])
        return prof

    def _default_profile(self) -> Profile:
        return Profile(strategy=self.s["strategy"], split_mode=self.s["split_mode"],
                       fooling=self.s["fooling"], fake_ttl=self.s["fake_ttl"],
                       fake_count=self.s["fake_count"], seg_count=self.s["seg_count"],
                       seqovl=self.s["seqovl"],
                       quic_mode=self.s["quic_mode"]).normalized()

    def _enabled_groups(self) -> list:
        g = self.s["groups"]
        return [gid for gid in services.GROUPS
                if g.get(gid, True) and services.has_card(gid)]

    def _logput(self, line) -> None:
        with self._lock:
            self.log.append(str(line))
            self._log_seq += 1

    def get_log(self, since=0) -> dict:
        """Только новые строки с момента `since`.

        Раньше весь лог (до 400 строк) ехал через мост каждую секунду — это
        была самая тяжёлая часть опроса. Теперь клиент присылает свой номер и
        получает только хвост; `reset`, если он отстал и начало уже вытеснено.
        """
        with self._lock:
            seq = self._log_seq
            first = seq - len(self.log)      # номер строки self.log[0]
            try:
                since = int(since)
            except (TypeError, ValueError):
                since = 0
            if since < first or since > seq:
                return {"seq": seq, "lines": list(self.log), "reset": True}
            return {"seq": seq, "lines": list(self.log)[since - first:], "reset": False}

    # -- состояние для интерфейса ------------------------------------------
    def get_state(self) -> dict:
        with self._lock:
            eng = self.engine
            # движок поднялся — переводим «запускается» в «работает»
            if self.state == "starting" and eng is not None and eng.running:
                self.state = "running"
            state = self.state
            log_seq = self._log_seq
            auto = dict(self.auto)

        running = state == "running"
        if running and eng is not None and eng.stats.get("started"):
            st = eng.stats
            dur = int(time.time() - st["started"])
            stats = {"duration_s": dur, "packets": st["packets"],
                     "bytes": st["bytes"], "hits": st["tcp"] + st["quic"]}
        else:
            stats = {"duration_s": 0, "packets": 0, "bytes": 0, "hits": 0}

        on = self.s["groups"]
        groups = []
        for gid, meta in services.GROUPS.items():
            # Telegram карточки не имеет: обойти его нельзя, у него своя вкладка
            if not services.has_card(gid):
                continue
            own = self.s["profiles"].get(gid)
            v = self.diag.get(gid, "")
            groups.append({
                "id": gid,
                "title": meta["title"],
                "icon": meta["icon"],
                "accent": meta["accent"],
                "enabled": bool(on.get(gid, True)),
                "tuned": bool(own),
                "profile": self._profile_of(gid).label(),
                "voice": bool(services.udp_range(gid)),
                "diag": v,
                "diag_text": diagnose.VERDICT_TEXT.get(v, ""),
                "hopeless": diagnose.hopeless(v),
            })
        return {
            "admin": is_admin(),
            "state": state,
            "running": running,
            "strategy": self.s["strategy"],
            "quic": self.s["quic_mode"],
            "fooling": self.s["fooling"],
            "split_mode": self.s["split_mode"],
            "fake_ttl": self.s["fake_ttl"],
            "fake_count": self.s["fake_count"],
            "seg_count": self.s["seg_count"],
            "seqovl": self.s["seqovl"],
            "all_traffic": self.s["all_traffic"],
            "voice": dict(self.voice),
            "voice_fake": self.s["voice_fake"],
            "voice_ttl": self.s["voice_ttl"],
            "voice_repeats": self.s["voice_repeats"],
            "watchdog": self.s["watchdog"],
            "groups": groups,
            "diag_running": self.diag_running,
            "anticheat": list(self.ac_found),
            "tg_proxy": dict(self.tg_proxy) if self.tg_proxy else None,
            "tg_searching": self.tg_searching,
            "tg_scan": dict(self.tg_scan) if self.tg_scan else None,
            "bridge": self.bridge_state(),
            "autostart": self.autostart_state(),
            "update": {**self.upd, "job": dict(self.updjob),
                       "later": self.upd_later},
            "conflicts": list(self.conflicts),
            "conflict_note": conflicts.summary(self.conflicts),
            "busy": self.busy(),
            "ac_paused": self.ac_paused,
            "pause_on_anticheat": self.s["pause_on_anticheat"],
            "proxy": diagnose.system_proxy(),
            # короткая подпись состава карточек — чтобы клиенту не сравнивать список
            "cats_sig": "".join(
                ("1" if g["enabled"] else "0") + ("t" if g["tuned"] else "-")
                + (g["diag"] or "_") for g in groups),
            "stats": stats,
            "auto": auto,
            "log_seq": log_seq,
        }

    def set(self, key, value):
        mapping = {"strategy": ("strategy", STRATEGIES), "quic": ("quic_mode", QUIC_MODES),
                   "fooling": ("fooling", FOOLINGS), "split_mode": ("split_mode", SPLITS)}
        nums = {"fake_ttl": (1, 64), "fake_count": (1, 8), "seg_count": (2, 6),
                "seqovl": (0, 1400)}
        if key in nums:
            lo, hi = nums[key]
            try:
                self.s[key] = max(lo, min(hi, int(value)))
            except (TypeError, ValueError):
                return False
        elif key in mapping:
            field, allowed = mapping[key]
            if value not in allowed:
                return False
            self.s[field] = value
        else:
            return False
        settings_store.save(self.s)
        return True

    def set_group(self, gid, on):
        if gid in self.s["groups"]:
            self.s["groups"][gid] = bool(on)
            self.s["categories"] = services.to_legacy_categories(self.s["groups"])
            settings_store.save(self.s)
        return True

    def clear_profile(self, gid):
        """Вернуть группу на общий профиль (сбросить подобранный)."""
        if self.s["profiles"].pop(gid, None) is not None:
            settings_store.save(self.s)
            self._logput(f"[*] {services.title(gid)}: свой обход сброшен.")
        return True

    def set_voice_ttl(self, value):
        """TTL голосовой подделки. 0 — не трогать (так надёжнее всего)."""
        self.s["voice_ttl"] = max(0, min(64, int(value or 0)))
        settings_store.save(self.s)
        return True

    def set_voice_repeats(self, value):
        self.s["voice_repeats"] = max(1, min(16, int(value or 6)))
        settings_store.save(self.s)
        return True

    def set_voice_fake(self, on):
        self.s["voice_fake"] = bool(on)
        settings_store.save(self.s)
        return True

    def set_pause_on_anticheat(self, on):
        self.s["pause_on_anticheat"] = bool(on)
        settings_store.save(self.s)
        return True

    def set_watchdog(self, on):
        self.s["watchdog"] = bool(on)
        settings_store.save(self.s)
        return True

    # старое имя — на случай, если где-то остался прежний вызов
    def set_category(self, cat, on):
        for gid in services.LEGACY_MAP.get(cat, []):
            self.set_group(gid, on)
        return True

    def set_all_traffic(self, on):
        self.s["all_traffic"] = bool(on)
        settings_store.save(self.s)
        return True

    # -- запуск / остановка ------------------------------------------------
    def toggle(self):
        with self._lock:
            state = self.state
        if state in ("running", "starting"):
            return self.stop()
        if state == "stopping":
            return False
        return self.start()

    def start(self):
        with self._lock:
            if self.auto["running"]:
                self._logput("[!] Идёт автоподбор — дождись завершения.")
                return False
            if not is_admin():
                self._logput("[!] Нет прав администратора — обход не запустится.")
                return False
            if self.state in ("starting", "running"):
                return True
            if self.state == "stopping":
                self._logput("[*] Останавливаюсь — повтори через секунду.")
                return False
            # Движок держим в локальной переменной и передаём в поток явно:
            # если бы поток читал self.engine, он мог бы взять уже другой
            # экземпляр и запустить его вторично.
            eng = Engine(self._build_config(), logger=self._logput)
            self.engine = eng
            self.state = "starting"
            self.thread = threading.Thread(target=self._run_engine, args=(eng,),
                                           daemon=True, name="rz-engine")
            self.thread.start()
        return True

    def _run_engine(self, eng):
        try:
            eng.run()
        except Exception as exc:  # noqa: BLE001
            self._logput(f"[!] {exc}")
        finally:
            with self._lock:
                # сверяем по личности: за время работы мог появиться преемник,
                # и затирать его состояние нельзя
                if self.engine is eng:
                    self.engine = None
                    self.thread = None
                    self.state = "idle"

    def stop(self):
        with self._lock:
            eng, th = self.engine, self.thread
            if eng is None:
                self.state = "idle"
                return False
            if self.state == "stopping":
                return False
            self.state = "stopping"
        # сам stop() не блокирует — он лишь закрывает дескриптор; дожидаемся
        # завершения потока отдельно, чтобы не подвесить поток JS-моста
        eng.stop()
        threading.Thread(target=self._finish_stop, args=(eng, th),
                         daemon=True, name="rz-stop").start()
        return False

    def _finish_stop(self, eng, th):
        if th is not None:
            th.join(timeout=5)
        with self._lock:
            if self.engine is eng:
                self.engine = None
                self.thread = None
                self.state = "idle"
                if th is not None and th.is_alive():
                    self._logput("[!] Поток обхода не завершился за 5 с — состояние сброшено.")

    def shutdown(self):
        """Погасить движок перед выходом, чтобы не бросать драйвер открытым."""
        self._watch_stop.set()
        self._bridge_stop.set()
        if self.bridge:
            self.bridge.stop()
        with self._lock:
            eng, th = self.engine, self.thread
            self.state = "stopping"
        if eng is not None:
            try:
                eng.stop()
            except Exception:
                pass
            if th is not None:
                th.join(timeout=4)
        # Дать драйверу выгрузиться, прежде чем закрываться. Служба WinDivert
        # прописана ВНУТРЬ распакованной папки программы, и пока драйвер
        # загружен, Windows держит её файл — папка не удаляется, а на выходе
        # вылезает «Failed to remove temporary directory».
        tempclean.wait_driver_gone(2.5)

    def elevate(self):
        self.shutdown()
        relaunch_as_admin()
        for w in list(webview.windows):
            try:
                w.destroy()
            except Exception:
                pass
        os._exit(0)

    def _build_config(self) -> Config:
        cfg = Config()
        cfg.strategy = self.s["strategy"]
        cfg.quic_mode = self.s["quic_mode"]
        cfg.fooling = self.s["fooling"]
        cfg.split_mode = self.s["split_mode"]
        cfg.fake_ttl = int(self.s["fake_ttl"])
        cfg.fake_count = int(self.s["fake_count"])
        cfg.seg_count = int(self.s["seg_count"])
        cfg.seqovl = int(self.s["seqovl"])

        enabled = self._enabled_groups()
        cards = list(enabled)          # что включил человек, до отбора по диагнозу

        # Трогаем ТОЛЬКО то, что доказанно заблокировано по имени сайта.
        #
        # Десинхронизация не бесплатна: рабочему сервису она способна сломать
        # соединение. Именно так и ломались лаунчер Epic, игры Steam и сайты
        # нейросетей — они не заблокированы вовсе, а обход применялся ко всему
        # подряд. Поэтому правило перевёрнуто: не «обходим всё, кроме
        # исключений», а «обходим только то, где диагностика увидела блокировку».
        #
        # `sni`/`unknown` — десинк уместен. `ok` — сервис работает сам.
        # `ip`/`ip-relay`/`dns` — соединения нет вовсе, десинк бессилен.
        # Группа со своим подобранным профилем идёт в обход всегда: раз
        # пользователь его подобрал, значит там было что обходить.
        FIXABLE = ("sni", "unknown")
        remembered = set(self.s.get("blocked_seen") or ())
        active, skip, unknown = [], [], []
        for g in enabled:
            v = self.diag.get(g)
            if self.s["profiles"].get(g) or v in FIXABLE or g in remembered:
                active.append(g)
            elif v is None:
                unknown.append(g)          # ещё не проверяли — решим ниже
            else:
                skip.append(g)
        # Непроверенные не трогаем: сломать рабочий сервис хуже, чем не обойти
        # заблокированный. Диагностика идёт при запуске и всё расставит.
        if unknown:
            self._logput("[*] Ещё не проверено, поэтому не трогаю: "
                         + ", ".join(services.title(g) for g in unknown)
                         + ". Нажми «Проверить сейчас».")
            skip.extend(unknown)
        if skip:
            self._logput("[*] Не трогаю (не заблокировано или десинк не поможет): "
                         + ", ".join(services.title(g) for g in skip))
        if active:
            self._logput("[*] Обхожу: " + ", ".join(services.title(g) for g in active))

        cfg.exclude = set(services.NEVER_TOUCH) | services.domains_for(skip)
        cfg.profiles = {gid: self._profile_of(gid) for gid in active}
        enabled = active
        if self.s["all_traffic"]:
            # «весь трафик» — список хостов пуст, группы всё равно нужны:
            # по ним движок соберёт фильтр и режимы QUIC
            cfg.host_groups = {}
            cfg.hosts = set()
        else:
            cfg.host_groups = services.host_group_map(enabled)
            cfg.hosts = set(cfg.host_groups)
        # Голосовой UDP — по галочке пользователя, а НЕ по диагнозу.
        #
        # Здесь и была настоящая причина, по которой у друга демонстрация
        # экрана не работала совсем: диагностика проверяет discord.com и
        # gateway.discord.gg, они в России открываются, группа получает
        # вердикт «ok» и уезжает в «не трогаю» — вместе с голосом. А голос
        # диагностика не проверяет вообще: он ходит по UDP, а не по TLS.
        # Поэтому берём карточки, включённые человеком, до отбора по диагнозу.
        cfg.udp_ranges = ({gid: services.udp_range(gid) for gid in cards
                           if services.udp_range(gid)}
                          if self.s["voice_fake"] else {})
        return cfg

    def _hosts(self) -> set:
        if self.s["all_traffic"]:
            return set()
        return services.domains_for(self._enabled_groups())

    # -- автоподбор --------------------------------------------------------
    def _auto_refuse(self, text: str) -> bool:
        """Отказ запустить подбор — с причиной НА ЭКРАНЕ.

        Раньше причина уходила только в журнал, а он свёрнут. Со стороны это
        выглядело как «нажал, и ничего не произошло».
        """
        self._logput("[!] " + text)
        self.auto.update({"running": False, "progress": 0.0, "eta": 0,
                          "status": text, "best": None, "matrix": []})
        return False

    def run_autotune(self, only=None, by_user=True, avoid_current=False):
        with self._lock:
            if self.auto["running"] or self.diag_running:
                return self._auto_refuse("Дождись окончания текущей проверки.")
            # Поиск Telegram открывает сотни соединений разом (подсети сканируются
            # пулом на 160 потоков). Одновременно с подбором это гарантированно
            # портит замеры: рукопожатия начинают упираться в таймаут, и
            # кандидаты валятся не потому, что плохи.
            if self.tg_searching or self.bridge_scan.get("running"):
                return self._auto_refuse(
                    "Идёт поиск прокси для Telegram — он забивает сеть, и замеры "
                    "подбора будут врать. Дождись его или отмени.")
            if self.state in ("starting", "stopping"):
                return self._auto_refuse(
                    "Обход сейчас переключается — дай ему секунду и повтори.")
            # Обход выключаем САМИ и включаем обратно в конце. Раньше здесь был
            # отказ «сначала выключи обход»: человек выключал, подбирал и
            # оставался с выключенным обходом, гадая, почему ничего не
            # работает. Драйвер всё равно нужен подбору одному, но помнить об
            # этом должна программа, а не человек.
            restore = (self.state == "running")
            if not is_admin():
                return self._auto_refuse(
                    "Нужны права администратора: закрой программу и запусти "
                    "правой кнопкой -> «Запуск от имени администратора».")
            self._auto_gen += 1
            gen = self._auto_gen
            self._auto_stop.clear()
            # Флаг ставим ДО старта потока, иначе два быстрых клика заводят два
            # воркера. Словарь мутируем, а не пересоздаём: иначе отставший
            # воркер писал бы в осиротевший объект и флаг залипал бы в True.
            targets = only if only else self._enabled_groups()
            self.auto.clear()
            self.auto.update({
                "running": True, "progress": 0.02, "eta": 0,
                "status": "Проверяю базовую доступность…", "best": None,
                "matrix": [{"id": g, "title": services.title(g),
                            "icon": services.GROUPS[g]["icon"],
                            "state": "wait", "label": ""} for g in targets],
            })
            self._avoid_current = bool(avoid_current)
            self._auto_thread = threading.Thread(
                target=self._auto_worker,
                args=(gen, list(targets), by_user, restore),
                daemon=True, name="rz-auto")
            self._auto_thread.start()
        return True

    def voice_report(self, quiet: bool = False) -> dict:
        """Готов ли Discord к голосу и демонстрации экрана.

        Снаружи можно проверить только инфраструктуру: адрес голосового
        сервера выдаётся под сессию, уже после входа в канал. Поэтому здесь
        честно — «шлюз и голосовые серверы открываются, клиент запущен, RPC
        отвечает», а не «звук точно пойдёт».
        """
        try:
            state = voicecheck.report()
        except Exception as exc:                     # noqa: BLE001
            return {"ok": False, "text": f"Проверить не вышло: {exc}"}
        # Сколько раз движок видел определение адреса голосового сервера.
        # Это единственный признак, по которому видно, доходит ли до нас
        # голосовой обмен вообще — или дело не в стратегии, а в том, что
        # трафик до нас не долетает.
        eng = self.engine
        seen = 0
        try:
            if eng is not None:
                seen = int(eng.stats.get("voice_seen", 0))
        except Exception:                             # noqa: BLE001
            seen = 0
        state["seen"] = seen
        self.voice = dict(state)
        if not quiet:
            self._logput("[*] Discord: " + state["text"])
            if state.get("rpc"):
                self._logput(f"    Клиент отвечает на 127.0.0.1:{state['rpc']} — "
                             f"игры и оверлеи его видят.")
            if self.state == "running" and services.udp_range("discord"):
                if seen:
                    self._logput(f"    Голосовое подключение через обход прошло "
                                 f"{seen} раз(а) — пакеты до нас доходят.")
                else:
                    self._logput("    Голосового подключения обход пока не видел. "
                                 "Зайди в канал при включённом обходе и посмотри "
                                 "сюда снова: если строки так и не будет, значит "
                                 "голосовой трафик до нас не доходит, и дело не "
                                 "в стратегии.")
        return state

    def retune_group(self, gid):
        """Подобрать обход заново для ОДНОЙ группы, поверх прежнего выбора.

        Полный подбор идёт минутами и трогает все группы разом. Обычно же
        отвалился один сервис, а остальные работают — и перебирать их заново
        незачем, как незачем и терять по ним уже подобранное.
        """
        if gid not in services.GROUPS:
            return self._auto_refuse("Неизвестная группа.")
        if diagnose.hopeless(self.diag.get(gid, "")):
            return self._auto_refuse(
                f"{services.title(gid)}: соединение не устанавливается вовсе — "
                f"обходить нечего, нужен прокси или VPN.")
        if self.s.get("profiles", {}).get(gid):
            self._logput(f"[*] Подбираю заново для {services.title(gid)} — "
                         f"прежний выбор в этот раз пропускаю, иначе он снова "
                         f"победит и ничего не изменится.")
        else:
            self._logput(f"[*] Подбираю только для {services.title(gid)}.")
        return self.run_autotune(only=[gid], avoid_current=True)

    def stop_autotune(self):
        """Прервать подбор. Уже подобранное не пропадает."""
        with self._lock:
            if not self.auto.get("running"):
                return False
        self._auto_stop.set()
        self.auto["status"] = "Останавливаю…"
        self._logput("[*] Подбор остановлен вручную.")
        return True

    def _mx(self, gid, state, label=""):
        """Отметить группу в матрице подбора (её видно в интерфейсе)."""
        for row in self.auto.get("matrix") or ():
            if row["id"] == gid:
                row["state"] = state
                if label:
                    row["label"] = label
                break

    def _auto_worker(self, gen, targets, by_user=True, restore=False):
        won = 0
        try:
            if restore and not self._pause_bypass():
                self.auto["status"] = "Не удалось выключить обход для подбора"
                return
            won = self._tune_groups(gen, targets)
        except Exception as exc:  # noqa: BLE001
            self.auto["status"] = "Ошибка автоподбора"
            self._logput(f"[!] Автоподбор: {exc}")
        finally:
            # Движок перебора живёт весь перебор целиком, поэтому гасим его
            # здесь: этот finally отрабатывает и при отмене, и при ошибке.
            sweep = getattr(self, "_sweep", None)
            if sweep is not None:
                sweep.stop()
                self._sweep = None
            with self._lock:
                # отставший воркер не должен снимать флаг с более нового запуска
                if gen == self._auto_gen:
                    self.auto["running"] = False
        if gen != self._auto_gen:
            return
        if restore:
            # Обход был включён до подбора — возвращаем как было, независимо
            # от того, нашлось что-нибудь или нет. Это ровно та кнопка,
            # которую человек уже нажимал; выключили её мы сами.
            self._logput("[*] Возвращаю обход в то состояние, в котором он был "
                         "до подбора.")
            self.start()
        elif won:
            if by_user:
                self._autostart_after_tune()
            else:
                # Подбор на старте программы обход НЕ включает: решение
                # «работать сейчас или нет» остаётся за человеком.
                self._logput("[*] Обход подобран. Включи его кнопкой, "
                             "когда понадобится.")

    def _tune_groups(self, gen, targets) -> int:
        """Подобрать обход для каждой группы отдельно. Возвращает число выигравших."""
        if not targets:
            self.auto["status"] = "Нечего подбирать — все группы выключены"
            return 0

        # 1. Сначала ДИАГНОЗ, а не перебор. Блокировку по IP не обходит ни одна
        # стратегия: соединение не устанавливается вообще, обманывать нечего.
        # Раньше такие группы честно перебирались две минуты и получали
        # «не пробило» — теперь они сразу помечаются причиной.
        self.auto["status"] = "Смотрю, чем закрыт каждый сервис…"
        verdicts = diagnose.classify_groups(targets)
        self.diag.update(verdicts)
        self.s["diag"] = dict(self.diag)
        self._remember_blocked(verdicts)
        settings_store.save(self.s)
        pending = []
        for gid in targets:
            v = verdicts.get(gid, "unknown")
            if v == "ok":
                self._mx(gid, "ok", "и так открывается")
            elif diagnose.hopeless(v):
                self._mx(gid, "hopeless", diagnose.VERDICT_TEXT[v])
                self._logput(f"[!] {services.title(gid)}: {diagnose.VERDICT_TEXT[v]} — "
                             f"обход DPI тут бессилен, нужен прокси или VPN.")
            else:
                pending.append(gid)
        good = sum(1 for v in verdicts.values() if v == "ok")
        self._logput(f"[*] Диагноз: {good}/{len(targets)} групп открывается без обхода.")

        proxy = diagnose.system_proxy()
        if proxy:
            self._logput(f"[*] Включён системный прокси ({proxy}). Приложения, которые "
                         f"его слушают, ходят через него, и обход им не нужен.")
        if not pending:
            self.auto["progress"] = 1.0
            self.auto["status"] = ("Перебирать нечего — смотри причины по каждой строке"
                                   if any(diagnose.hopeless(v) for v in verdicts.values())
                                   else "Всё и так открывается — обход не нужен")
            return 0

        cover = self._probe_extra()
        sweep = Sweep(pending, self.s["quic_mode"], cover)
        self._sweep = sweep               # гасится в _auto_worker

        # 1. Разрешить имена заранее. На холодную DNS занимает до секунды, и
        #    внутри проверки это выглядит как «сервер долго думал» — из-за
        #    чего таймаут и приходилось держать с запасом.
        self.auto["status"] = "Готовлюсь: разрешаю имена…"
        autotune.warm_dns(sweep.hosts + [autotune.CONTROL_HOST])

        # 2. Замерить, сколько на ЭТОЙ сети занимает заведомо успешное
        #    рукопожатие, и от него назначить таймаут перебора.
        scan_timeout = self._scan_timeout()

        # 3. Собрать план и выбросить из него близнецов.
        # полный план: сперва проверенные комбинации, затем сетка добора.
        # Без сетки подбор упирался в список и сдавался — а youtubei
        # берётся только ею.
        avoid = bool(getattr(self, "_avoid_current", False))
        if avoid:
            # Человек нажал «подобрать заново» ИМЕННО потому, что нынешняя
            # стратегия его не устраивает. Отдать её обратно — издевательство:
            # она стоит первой в очереди, проходит проверку (по TCP-хостам она
            # и правда работает) и выигрывает, а проблема остаётся.
            combos = autotune.all_candidates()
            combos = [c for c in combos if not self._is_current(c, targets)]
        else:
            combos = autotune.all_candidates(self._known_good())
        before = len(combos)
        combos = self._dedupe_plan(combos, sweep.hosts)
        per = scan_timeout + SWEEP_OVERHEAD
        self._logput(
            f"[*] План: {len(combos)} проверок "
            f"(одинаковых отсеяно: {before - len(combos)}), таймаут "
            f"{scan_timeout:.1f} с, полный перебор — до "
            f"{max(1, int(len(combos) * per / 60))} мин.")
        finalists: dict = {}          # {группа: [прошедшие комбинации]}
        first_hit: dict = {}          # {группа: номер её первой удачи}
        won = {}
        open_fails = 0

        for i, combo in enumerate(combos):
            if gen != self._auto_gen:      # запуск отменён более новым
                return len(won)
            if self._auto_stop.is_set():
                self.auto["status"] = (f"Остановлено — подобрано {len(won)}"
                                       if won else "Остановлено")
                for gid in pending:
                    self._mx(gid, "wait", "не успели")
                break
            # у кого уже есть хоть один рабочий вариант и окно поиска вышло —
            # хватит, лучшее выберем из того, что нашлось
            for gid in list(pending):
                if gid in first_hit and i - first_hit[gid] >= EXTRA_SCAN:
                    pending.remove(gid)
            if not pending:
                break
            self.auto["progress"] = max(0.03, i / len(combos))
            self.auto["eta"] = (int((len(combos) - i) * per) if pending else 0)
            self.auto["status"] = f"Проверяю: {combo['label']} ({i + 1}/{len(combos)})"
            for gid in pending:
                self._mx(gid, "test")

            ok, opened = self._test_candidate(combo, pending,
                                              timeout=scan_timeout, sweep=sweep)
            if not opened:
                open_fails += 1
                # проблема с драйвером, а не со стратегией: две минуты молчаливых
                # неудач тут никому не помогут
                if open_fails >= 2:
                    why = getattr(self, "_last_open_error", "") or "причина неизвестна"
                    self.auto["status"] = "Драйвер WinDivert не открывается"
                    self._logput(f"[!] WinDivert не открывается ({why}) — подбор "
                                 f"прерван.")
                    self._logput("    Обычно причина одна из трёх: программа "
                                 "запущена не от администратора; драйвер выгрыз "
                                 "антивирус; уже работает другая программа обхода "
                                 "(zapret, GoodbyeDPI) и держит драйвер.")
                    return len(won)
                continue
            open_fails = 0

            maybe = [gid for gid in list(pending) if ok.get(gid)]
            for gid in pending:
                if gid not in maybe:
                    self._mx(gid, "wait")
            if not maybe:
                continue

            # КОНТРОЛЬНЫЙ ПРОГОН. Блокировка мигает: одна удачная проверка
            # случается и без обхода. Раньше её хватало, чтобы закрепить
            # стратегию, — и «подобранный» YouTube работал через раз.
            # Теперь победитель обязан подтвердиться вторым независимым
            # замером, и уже с тремя рукопожатиями подряд на каждый хост.
            self.auto["status"] = f"Перепроверяю: {combo['label']}"
            for gid in maybe:
                self._mx(gid, "test")
            # Живые имена ПОДКЛЮЧАЕМ к движку (обход должен их накрыть), но
            # решать «прошло/не прошло» по ним НЕЛЬЗЯ. Имена вида
            # rr4---sn-4g5edndl.googlevideo.com выдаются под сессию: через
            # час-другой к ним уже не подключиться никакой стратегией. А раз
            # проверка требует, чтобы прошли ВСЕ хосты, одно такое имя
            # заваливает подряд всех кандидатов — ровно это и случилось на
            # чужой машине: перебрали весь список, «не подтвердилось» у всех,
            # включая ту стратегию, которая десятью минутами раньше дала 100%.
            # Их место — в подсчёте очков финала, где они РАНЖИРУЮТ, а не
            # отсеивают.
            ok2, opened2 = self._test_candidate(combo, maybe, tries=3,
                                                timeout=CHECK_TIMEOUT,
                                                cover=cover, sweep=sweep)

            hit, flaky = [], []
            for gid in maybe:
                if opened2 and not ok2.get(gid):
                    flaky.append(services.title(gid))
                    self._mx(gid, "wait")
                    continue
                # НЕ закрепляем сразу: копим несколько прошедших и в конце
                # выбираем лучшего по счёту. «Первый сработавший» -- не то же
                # самое, что «лучший»: YouTube открывался, а видео не шло.
                finalists.setdefault(gid, []).append(combo)
                if gid not in first_hit:
                    # ЗАКРЕПЛЯЕМ СРАЗУ, не дожидаясь финала. Подбор долгий, и
                    # его часто прерывают на середине — раньше всё найденное
                    # к этому моменту оставалось только в памяти. Финал потом
                    # перезапишет профиль, если найдёт вариант получше.
                    self._pin_profile(gid, combo)
                first_hit.setdefault(gid, i)
                self._mx(gid, "ok", combo["label"])
                hit.append(services.title(gid))
                if len(finalists[gid]) >= FINALISTS:
                    pending.remove(gid)
            if hit:
                self._logput(f"[*] {combo['label']} -> пробило: {', '.join(hit)}")
            if flaky:
                self._logput(f"[~] {combo['label']} -> у {', '.join(flaky)} "
                             "не подтвердилось, ищу дальше.")

        # Второй заход для тех, у кого пусто. Перебор шёл с таймаутом по
        # замеру сети; если мы всё же поторопились, потерять могли только
        # медленно отвечающего кандидата — а такой скорее найдётся в начале
        # списка, среди проверенных временем связок.
        empty = [gid for gid in targets
                 if not finalists.get(gid)
                 and verdicts.get(gid) != "ok"
                 and not diagnose.hopeless(verdicts.get(gid, "unknown"))]
        if empty and not self._auto_stop.is_set() and gen == self._auto_gen:
            self._second_pass(empty, combos, finalists, first_hit, sweep, gen)

        # Финал считает очки своим движком с другим набором имён — общий
        # больше не нужен, и держать драйвер открытым просто так незачем.
        sweep.stop()
        self._sweep = None
        won = self._playoff(finalists, gen)

        for gid in pending:
            if gid not in won:
                self._mx(gid, "fail", "не пробило ничем")

        # 2. сохранить: своей группе — свой профиль
        for gid, combo in won.items():
            self._pin_profile(gid, combo, save=False)

        if won:
            # самый частый победитель становится общим профилем — им работают
            # группы без своего и CLI
            top = collections.Counter(c["label"] for c in won.values()).most_common(1)[0][0]
            best = next(c for c in won.values() if c["label"] == top)
            self.s["strategy"] = best["strategy"]
            self.s["fooling"] = best.get("fooling", self.s["fooling"])
            self.s["split_mode"] = best.get("split", self.s["split_mode"])
            self.s["fake_ttl"] = int(best.get("ttl", self.s["fake_ttl"]))
            self.s["fake_count"] = int(best.get("fakes", 1))
            self.s["seg_count"] = int(best.get("segs", self.s["seg_count"]))
            self.s["seqovl"] = int(best.get("ovl", 0))
            self.auto["best"] = f"{len(won)} из {len(targets)} групп подобрано"
            self.auto["status"] = ("Остановлено — подобранное применено"
                                   if self._auto_stop.is_set() else "Готово — применено")
            self._logput("[*] Подобрано: " + "; ".join(
                f"{services.title(g)} = {c['label']}" for g, c in won.items()))
        elif self._auto_stop.is_set():
            # человек прервал сам -- «ничего не пробило» тут было бы враньём:
            # до большей части списка просто не дошли
            self.auto["status"] = "Остановлено"
        elif avoid:
            # Прежний выбор мы намеренно исключили и ничего другого не нашли.
            # Значит он и есть лучшее из доступного — но человек должен
            # понимать, что это не «подобралось заново», а «замены нет».
            kept = [g for g in targets if self.s["profiles"].get(g)]
            self.auto["status"] = "Замены не нашлось — оставил прежнее"
            self._logput(
                "[!] Ничего другого не пробило. Прежний выбор оставлен, но он "
                "уже показал себя не с лучшей стороны — если дело в голосе "
                "Discord, обход DPI ему может быть просто не по силам: "
                "смотри «Готов ли голос» в журнале.")
        else:
            kept = [g for g in targets if self.s["profiles"].get(g)]
            if kept:
                # Важно сказать вслух: прежний выбор НЕ стёрт. Иначе «ничего не
                # пробило» читается как «всё пропало», хотя работавшая
                # настройка осталась на месте.
                self.auto["status"] = ("Ничего нового не нашлось — прежние "
                                       "настройки остались")
                self._logput("[*] Ничего нового не пробило. Прежний выбор "
                             "оставлен без изменений: " + "; ".join(
                                 f"{services.title(g)} = "
                                 f"{Profile.from_dict(self.s['profiles'][g]).label()}"
                                 for g in kept))
            else:
                self.auto["status"] = "Ничего не пробило — попробуй вручную"
                self._logput("[!] Автоподбор ничего не пробил.")

        # Если среди подобранного был Discord — сразу сказать, что с голосом.
        # Иначе человек видит «Discord = такая-то стратегия» и всё равно не
        # знает, заработает ли демонстрация экрана.
        # ...но не после отмены: человек нажал «остановить» и ждёт, что
        # остановится, а проверка лезет в сеть и держит его ещё несколько
        # секунд. Отмена должна быть отменой.
        if ("discord" in targets and gen == self._auto_gen
                and not self._auto_stop.is_set()):
            self.voice_report()

        self.s["auto_tuned"] = True
        settings_store.save(self.s)
        self.auto["progress"] = 1.0
        self.auto["eta"] = 0
        return len(won)

    def _pause_bypass(self, wait: float = 8.0) -> bool:
        """Погасить обход и дождаться, пока драйвер действительно освободится.

        Ждать обязательно: WinDivert держит один хозяин, и подбор, начатый
        раньше времени, упрётся в «драйвер не открывается» — причём выглядеть
        это будет как поломка, а не как спешка.
        """
        self._logput("[*] Выключаю обход на время подбора — драйвер нужен "
                     "ему одному.")
        self.stop()
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            with self._lock:
                if self.state == "idle":
                    return True
            time.sleep(0.1)
        self._logput("[!] Обход не выключился за отведённое время — подбор "
                     "отменён, чтобы не мешать самому себе.")
        return False

    def _autostart_after_tune(self):
        """Включить обход сразу после подбора, который запросил человек.

        Подбор поднимает и гасит свой движок, поэтому в конце обход выключен —
        и это сбивало с толку: настройки подобраны, а ничего не работает,
        потому что кнопку никто не нажал.

        Вызывается ТОЛЬКО когда подбор нажали руками. Подбор при запуске
        программы обход не включает: программа не решает за человека, работать
        ей сейчас или нет.
        """
        with self._lock:
            if self.state != "idle" or self.auto["running"]:
                return
        if not self.s["profiles"]:
            return
        self._logput("[*] Включаю обход с подобранными настройками.")
        self.start()

    def _pin_profile(self, gid, combo, save: bool = True) -> None:
        """Закрепить за группой подобранную комбинацию."""
        prof = autotune.candidate_to_profile(
            combo, quic_mode=self.s["quic_mode"],
            udp_fake=bool(services.udp_range(gid)) and self.s["voice_fake"])
        self.s["profiles"][gid] = prof.to_dict()
        if save:
            settings_store.save(self.s)
            self._logput(f"[*] {services.title(gid)}: «{combo['label']}» "
                         f"закреплён — прервёшь подбор, он останется.")

    def _second_pass(self, groups, combos, finalists, first_hit, sweep, gen) -> None:
        """Ещё раз по началу списка, уже без спешки.

        Нужен ровно затем, чтобы быстрый перебор можно было держать быстрым.
        Цена — полторы минуты, и только в случае, когда всё равно не нашлось
        ничего и человек иначе остался бы ни с чем.
        """
        head = [c for c in combos if not c.get("grid")][:SECOND_PASS]
        if not head:
            return
        self._logput(f"[*] Ничего не пробило. Перепроверяю {len(head)} связок "
                     f"не спеша (таймаут {CHECK_TIMEOUT} с) — вдруг стратегия "
                     f"рабочая, просто отвечает медленно.")
        pending = list(groups)
        for gid in pending:
            self._mx(gid, "test")
        for i, combo in enumerate(head):
            if not pending or self._auto_stop.is_set() or gen != self._auto_gen:
                break
            self.auto["status"] = (f"Второй заход: {combo['label']} "
                                   f"({i + 1}/{len(head)})")
            ok, opened = self._test_candidate(combo, pending, tries=2,
                                              timeout=CHECK_TIMEOUT, sweep=sweep)
            if not opened:
                return
            maybe = [g for g in pending if ok.get(g)]
            if not maybe:
                continue
            # Контрольный прогон обязателен и здесь. Второй заход существует
            # ради терпения, а не ради снисходительности: одна удачная
            # проверка случается и без обхода, и раньше подбор на это
            # покупался — «подобранный» сервис работал через раз.
            ok2, opened2 = self._test_candidate(combo, maybe, tries=3,
                                                timeout=CHECK_TIMEOUT, sweep=sweep)
            if not opened2:
                return
            for gid in [g for g in maybe if ok2.get(g)]:
                finalists.setdefault(gid, []).append(combo)
                first_hit.setdefault(gid, 10 ** 6)
                self._pin_profile(gid, combo)
                self._mx(gid, "ok", combo["label"])
                pending.remove(gid)
                self._logput(f"[*] {services.title(gid)}: со вторым заходом "
                             f"подошло «{combo['label']}».")
        for gid in pending:
            self._mx(gid, "fail", "не пробило ничем")

    def _scan_timeout(self) -> float:
        """Таймаут одной проверки — по замеру этой сети, а не «на всякий случай».

        Заблокированный хост не отвечает отказом, он молчит до упора. Значит
        таймаут и есть цена одной неудачной проверки, а неудачных в переборе
        подавляющее большинство: именно он определяет, двадцать минут пойдёт
        подбор или восемь.

        Держать его фиксированным приходилось из-за неизвестности: сеть может
        быть медленной. Но её несложно измерить. Замер берётся по заведомо
        незаблокированному хосту, с шестикратным запасом — этого хватает и на
        переупорядоченные сегменты, которые сервер иногда ждёт лишний круг.
        А на случай, если запаса всё же не хватило, есть второй заход:
        группа, не нашедшая ничего, перепроверяется по началу списка уже без
        спешки (см. _second_pass).
        """
        base = 0.0
        try:
            base = autotune.baseline_latency()
        except Exception:                             # noqa: BLE001
            base = 0.0
        if base <= 0:
            # замерить не вышло (нет сети?) — остаёмся на прежнем значении
            self._logput("[*] Скорость сети замерить не удалось, "
                         f"таймаут проверки прежний: {SCAN_TIMEOUT} с.")
            return SCAN_TIMEOUT
        want = max(SCAN_TIMEOUT_MIN, min(SCAN_TIMEOUT, base * SCAN_MARGIN))
        self._logput(f"[*] Рукопожатие на этой сети занимает {base:.2f} с — "
                     f"жду ответа {want:.1f} с вместо {SCAN_TIMEOUT}.")
        return want

    def _dedupe_plan(self, combos, hosts) -> list:
        """Выбросить комбинации, которые дают ОДИНАКОВЫЕ пакеты.

        Точка разреза считается от имени сайта, и разные подписи нередко
        сходятся в одно и то же место: «первая буква имени» и «начало имени
        плюс один» — это буквально один и тот же байт. Проверять обе — значит
        дважды ждать один и тот же таймаут.

        Сравниваем не подписи, а результат: техника, обман, подделки и
        посчитанные точки разреза на НАСТОЯЩИХ проверочных именах.
        """
        try:
            probe = Engine(Config(), logger=lambda *_: None)
            hellos = []
            for host in hosts[:8]:
                payload = _client_hello(host)
                span = protocols.find_sni(payload) if payload else None
                if span:
                    hellos.append((host, payload, span[0], span[1]))
            if not hellos:
                return list(combos)
        except Exception:                             # noqa: BLE001
            return list(combos)

        out, seen = [], set()
        for combo in combos:
            try:
                prof = autotune.candidate_to_profile(combo)
                cuts = tuple(
                    tuple(probe._positions(a, b, len(pl), prof, host))
                    for host, pl, a, b in hellos)
                key = (prof.strategy, prof.fooling, prof.fake_ttl, prof.fake_count,
                       prof.seqovl, prof.ip_id_zero, prof.fake_sni, cuts)
            except Exception:                         # noqa: BLE001
                out.append(combo)
                continue
            if key in seen:
                continue
            seen.add(key)
            out.append(combo)
        return out

    def _is_current(self, combo, groups) -> bool:
        """Совпадает ли комбинация с тем, что уже стоит у этих групп."""
        try:
            mine = autotune.candidate_to_profile(combo).to_dict()
        except Exception:                             # noqa: BLE001
            return False
        for gid in groups:
            body = (self.s.get("profiles") or {}).get(gid)
            if not body:
                continue
            try:
                theirs = Profile.from_dict(body).to_dict()
            except Exception:                         # noqa: BLE001
                continue
            same = all(mine.get(k) == theirs.get(k) for k in
                       ("strategy", "split_mode", "fooling", "fake_ttl",
                        "fake_count", "seg_count", "seqovl", "ip_id_zero",
                        "fake_sni"))
            if same:
                return True
        return False

    def _known_good(self) -> list:
        """Комбинации, которые уже работали на этой машине, — первыми в очередь.

        Сеть и провайдер у человека те же, что в прошлый раз, поэтому прошлый
        ответ верен куда чаще любого кандидата из общего списка. Стоит проверка
        одну итерацию, а выигрывает, когда подбор запускают повторно, — минуты.
        """
        out = []
        for gid, body in (self.s.get("profiles") or {}).items():
            c = autotune.profile_to_candidate(
                body, f"прошлый выбор: {services.title(gid)}")
            if c is not None:
                out.append(c)
        return out

    def _playoff(self, finalists: dict, gen: int) -> dict:
        """Из прошедших комбинаций выбрать для каждой группы лучшую.

        Проверка «прошло/не прошло» слишком груба: две стратегии проходят
        одинаково, а работают по-разному. Здесь каждый финалист гоняется ещё
        раз с подсчётом КАЖДОГО рукопожатия по каждому хосту, и группа
        достаётся тому, у кого счёт выше. При равном счёте побеждает тот, кто
        встретился раньше — список идёт от щадящих техник к тяжёлым.
        """
        if not finalists:
            return {}
        # один и тот же кандидат часто финалист сразу у нескольких групп —
        # гоняем его один раз на всех
        uniq: list = []
        for lst in finalists.values():
            for c in lst:
                if c not in uniq:
                    uniq.append(c)
        single = all(len(v) <= 1 for v in finalists.values())
        if single:
            return {gid: lst[0] for gid, lst in finalists.items() if lst}

        best: dict = {}
        scores: dict = {}
        for i, combo in enumerate(uniq):
            if gen != self._auto_gen or self._auto_stop.is_set():
                break
            groups = [g for g, lst in finalists.items() if combo in lst]
            if not groups:
                continue
            self.auto["status"] = f"Финал: {combo['label']} ({i + 1}/{len(uniq)})"
            for gid in groups:
                self._mx(gid, "test")
            got = self._score_candidate(combo, groups)
            for gid, (ok, total) in got.items():
                rank = (ok / total) if total else 0.0
                if rank > scores.get(gid, -1.0):
                    scores[gid] = rank
                    best[gid] = combo

        # кого не успели оценить — берём первого прошедшего, он честно прошёл
        for gid, lst in finalists.items():
            if gid not in best and lst:
                best[gid] = lst[0]
        for gid, combo in best.items():
            note = f" ({scores[gid] * 100:.0f}%)" if gid in scores else ""
            self._mx(gid, "ok", combo["label"])
            self._logput(f"[*] {services.title(gid)}: выбрано «{combo['label']}»"
                         f"{note} из {len(finalists.get(gid, []))} прошедших.")
        return best

    def _score_candidate(self, combo, groups) -> dict:
        """Счёт кандидата: сколько рукопожатий из скольких прошло."""
        prof = autotune.candidate_to_profile(combo, quic_mode=self.s["quic_mode"])
        cfg = Config()
        cfg.host_groups = {host: gid for gid, host in autotune.probe_targets(groups)}
        for gid, hosts in self._probe_extra().items():
            if gid in groups:
                for h in hosts:
                    cfg.host_groups[h] = gid
        cfg.hosts = set(cfg.host_groups)
        cfg.profiles = {gid: prof for gid in groups}
        eng = Engine(cfg, logger=lambda *_: None)
        th = threading.Thread(target=eng.run, daemon=True, name="rz-score")
        th.start()
        eng.ready.wait(timeout=5)
        try:
            if not eng.running:
                return {}
            time.sleep(0.1)
            return autotune.score_probes(groups, CHECK_TIMEOUT, rounds=3,
                                         extra=self._probe_extra())
        finally:
            eng.stop()
            th.join(timeout=4)
            time.sleep(0.1)

    def _test_candidate(self, combo, groups, tries=2, timeout=CHECK_TIMEOUT,
                        cover=None, sweep=None):
        """Прогнать одну комбинацию на проверочных хостах групп.

        Возвращает ({группа: пробило}, открылся ли драйвер). Второе важно
        отдельно: если WinDivert не открылся, все False означают не «не
        пробило», а «проверка не состоялась».

        `sweep` — общий движок перебора. С ним драйвер не трогается вовсе:
        достаточно подменить профиль. Без него (одиночный вызов, тесты)
        поднимается свой на одну проверку, как раньше.
        """
        prof = autotune.candidate_to_profile(combo, quic_mode=self.s["quic_mode"])
        if sweep is not None:
            if not sweep.alive() and not sweep.start():
                self._last_open_error = sweep.error
                return {}, False
            sweep.use(prof)
            time.sleep(0.05)              # дать смене профиля дойти до потока
            return autotune.test_probes(groups, timeout, tries), True

        own = Sweep(groups, self.s["quic_mode"], cover)
        if not own.start():
            # Причину знает только движок. Без неё «драйвер не открылся»
            # ничего не говорит человеку, который сидит далеко.
            self._last_open_error = own.error
            return {}, False
        try:
            own.use(prof)
            time.sleep(0.1)
            return autotune.test_probes(groups, timeout, tries), True
        finally:
            own.stop()
            time.sleep(0.1)

    def run_diagnose(self, progress=None):
        """Проверить прямо сейчас, чем закрыт каждый сервис.

        Это не подбор: ничего не перебирается и не меняется. Просто честный
        ответ на вопрос «что вообще происходит» — и он же говорит, есть ли
        смысл в обходе DPI для конкретной группы.
        """
        with self._lock:
            if self.diag_running or self.auto["running"]:
                self._logput("[!] Дождись окончания текущей проверки.")
                return False
            self.diag_running = True
        threading.Thread(target=self._diag_worker, args=(progress,),
                         daemon=True, name="rz-diag").start()
        return True

    def _diag_worker(self, progress=None):
        try:
            groups = self._enabled_groups() or list(services.GROUPS)
            self._logput("[*] Проверяю, чем закрыт каждый сервис…")
            res = diagnose.classify_groups(groups, progress=progress)
            self.diag = dict(res)
            self.s["diag"] = dict(res)
            self._remember_blocked(res)
            settings_store.save(self.s)
            for gid in groups:
                v = res.get(gid, "unknown")
                self._logput(f"    {services.title(gid)}: {diagnose.VERDICT_TEXT.get(v, v)}")
            proxy = diagnose.system_proxy()
            if proxy:
                self._logput(f"[*] Включён системный прокси ({proxy}) — приложения, "
                             f"которые его слушают, ходят мимо обхода.")
            relay = [services.title(g) for g, v in res.items() if v == "ip-relay"]
            hard = [services.title(g) for g, v in res.items()
                    if diagnose.hopeless(v) and v != "ip-relay"]
            if hard:
                self._logput("[!] Обходом DPI не решается: " + ", ".join(hard)
                             + ". Тут соединение не устанавливается вовсе — нужен прокси.")
            if relay:
                self._logput(
                    "[*] " + ", ".join(relay) + ": основные адреса закрыты по IP, "
                    "но открытая точка входа есть. Обход DPI тут не поможет, а "
                    "WebSocket-мост (tg-ws-proxy) — да, и без VPN.")
        except Exception as exc:  # noqa: BLE001
            self._logput(f"[!] Проверка: {exc}")
        finally:
            with self._lock:
                self.diag_running = False

    def busy(self) -> str:
        """Что сейчас занято. Поиск прокси сюда НЕ входит.

        Он не трогает драйвер и мешать подбору не может — а раньше входил, и
        из-за этого кнопка «найти прокси» была вечно заблокирована, пока шла
        любая другая проверка. Со стороны это выглядело как «не находит никак».
        """
        with self._lock:
            if self.auto["running"]:
                return "подбор"
            if self.diag_running:
                return "проверка"
        return ""

    # -- автозапуск с Windows ---------------------------------------------
    # -- обновления через GitHub ------------------------------------------
    def check_update(self):
        """Спросить у GitHub, есть ли релиз новее. Ничего не качает."""
        with self._lock:
            if self.upd.get("checking"):
                return False
            self.upd["checking"] = True
        threading.Thread(target=self._upd_worker, daemon=True, name="rz-upd").start()
        return True

    def _upd_worker(self):
        try:
            got = update.check()
        except Exception as exc:                     # noqa: BLE001
            got = {"current": update.VERSION, "latest": "", "newer": False,
                   "required": False, "url": update.RELEASES_URL, "notes": "",
                   "error": str(exc), "asset": "", "size": 0, "sha256": ""}
        with self._lock:
            self.upd.clear()
            self.upd.update(got)
            self.upd["checking"] = False
        if got.get("newer"):
            what = "Требуется обновление" if got.get("required") else "Есть новая версия"
            self._logput(f"[*] {what}: {got['latest']} (у тебя {update.VERSION}).")

    # -- установка обновления ---------------------------------------------
    def start_update(self):
        """Скачать и поставить новую версию. Зовётся ТОЛЬКО по согласию."""
        with self._lock:
            if self.updjob["running"]:
                return False
            url = self.upd.get("asset") or ""
            if not url:
                self._logput("[!] В релизе нет готового файла — открываю страницу.")
                threading.Thread(target=self.open_releases, daemon=True).start()
                return False
            self.updjob.update({"running": True, "stage": "download",
                                "done": 0, "total": int(self.upd.get("size") or 0),
                                "error": ""})
        threading.Thread(target=self._install_worker, daemon=True,
                         name="rz-install").start()
        return True

    def _install_worker(self):
        dest = update.staging_path()
        self._logput(f"[*] Скачиваю {self.upd.get('latest')}…")

        def on_bytes(done, total):
            self.updjob["done"] = done
            if total:
                self.updjob["total"] = total

        err = update.download(self.upd.get("asset", ""), dest, progress=on_bytes,
                              expect_size=int(self.upd.get("size") or 0),
                              sha256=self.upd.get("sha256", ""))
        if err:
            with self._lock:
                self.updjob.update({"running": False, "stage": "", "error": err})
            self._logput(f"[!] Обновление не скачалось: {err}")
            return

        self.updjob["stage"] = "install"
        self._logput("[*] Ставлю новую версию и перезапускаюсь.")
        err = update.install_and_restart(dest)
        if err:
            with self._lock:
                self.updjob.update({"running": False, "stage": "", "error": err})
            self._logput(f"[!] Установка не удалась: {err}")
            return

        # Новая копия уже запущена. Старое окно надо убрать НЕМЕДЛЕННО: пока
        # оно на экране, человек видит прежний интерфейс и решает, что
        # обновление ничего не сделало. Именно так и выглядела жалоба
        # «пофиксила только полная переустановка».
        try:
            win = globals().get("_window")
            if win is not None:
                win.hide()
        except Exception:                            # noqa: BLE001
            pass

        # Гасим драйвер — но не ждём этого вечно. Если движок или мост
        # подвиснут на остановке, старый процесс останется жить рядом с новым
        # и будет держать WinDivert. Даём четыре секунды и уходим в любом случае.
        done = threading.Event()

        def _quit():
            try:
                self.shutdown()
            except Exception:                        # noqa: BLE001
                pass
            done.set()

        threading.Thread(target=_quit, daemon=True, name="rz-quit").start()
        done.wait(6.5)
        os._exit(0)

    def dismiss_update(self):
        """«Позже»: убрать окно требования до следующего запуска."""
        self.upd_later = True
        return True

    def get_releases(self):
        """Журнал обновлений — список релизов с описаниями."""
        try:
            return update.releases()
        except Exception as exc:                     # noqa: BLE001
            return {"items": [], "error": str(exc)}

    def about(self):
        """Кто написал и куда смотреть."""
        return {"version": update.VERSION, "author": update.AUTHOR,
                "author_url": update.AUTHOR_URL, "repo": update.REPO_URL,
                "releases": update.RELEASES_URL, "issues": update.ISSUES_URL}

    def open_url(self, url):
        """Открыть ссылку в браузере. Только свои — чужие не открываем."""
        allowed = (update.REPO_URL, update.RELEASES_URL,
                   update.ISSUES_URL, update.AUTHOR_URL)
        if not (url in allowed or url.startswith(update.REPO_URL + "/")):
            self._logput("[!] Эта ссылка не из репозитория — не открываю.")
            return False
        try:
            webbrowser.open(url)
            return True
        except Exception as exc:                     # noqa: BLE001
            self._logput(f"[!] Не открылся браузер: {exc}")
            return False

    def open_releases(self):
        """Открыть страницу релизов в браузере. Скачивает человек, не мы."""
        url = self.upd.get("url") or update.RELEASES_URL
        try:
            webbrowser.open(url)
            return True
        except Exception as exc:                     # noqa: BLE001
            self._logput(f"[!] Не открылся браузер: {exc}")
            return False

    def autostart_state(self) -> bool:
        try:
            return autostart.is_enabled()
        except Exception:
            return False

    def set_autostart(self, on):
        """Включить/выключить запуск вместе с Windows.

        Задача создаётся в Планировщике с наивысшими правами — иначе обход
        стартовал бы без прав администратора и не смог бы открыть драйвер.
        """
        try:
            ok, msg = autostart.enable() if on else autostart.disable()
        except Exception as exc:  # noqa: BLE001
            self._logput(f"[!] Автозапуск: {exc}")
            return False
        self._logput(("[*] " if ok else "[!] ") + msg)
        if ok:
            self.s["autostart"] = bool(on)
            settings_store.save(self.s)
        return ok

    # -- Telegram: встроенный мост ----------------------------------------
    def bridge_state(self) -> dict:
        """Состояние моста БЕЗ адресов точек входа.

        Показывать их незачем: пользы ноль, а вред есть — увидев адрес, человек
        впишет его куда-нибудь руками, выключит программу и решит, что Telegram
        настроен. Мост живёт только вместе с приложением, и интерфейс не должен
        намекать на обратное.
        """
        br = self.bridge
        scan = self.bridge_scan
        return {"running": bool(br and br.running),
                "port": tgbridge.DEFAULT_PORT,
                "stats": dict(br.stats) if br else {},
                "scan": {"running": bool(scan.get("running")),
                         "step": int(scan.get("step") or 0),
                         "total": int(scan.get("total") or 0),
                         "found": len(scan.get("entries") or [])}}

    def telegram_connect(self):
        """Подключить Telegram: одно действие вместо двух кнопок.

        Кнопок было две — «найти вход» для встроенного моста и «найти прокси»
        для уже запущенного клиента, — и человеку приходилось гадать, какая
        из них ему нужна. Теперь порядок задан здесь: сначала пробуем
        обойтись своими силами, и только если не вышло — смотрим, нет ли
        чужого прокси. Обе части прерываются одной кнопкой «Отменить».
        """
        with self._lock:
            if self.tg_searching or self.bridge_scan["running"]:
                return False
            if self.auto.get("running"):
                self._logput("[!] Сейчас идёт подбор обхода. Поиск прокси забьёт "
                             "сеть и собьёт его замеры — дождись или останови "
                             "подбор.")
                return False
            self.tg_searching = True
        self._bridge_stop.clear()
        threading.Thread(target=self._connect_worker, daemon=True,
                         name="rz-tgfind").start()
        return True

    def telegram_stop(self):
        """Прервать поиск на любом его шаге."""
        self._bridge_stop.set()
        return True

    def _find_entries(self) -> list:
        """Шаг 1: живая точка входа для собственного моста."""
        def progress(net, i, total):
            self.bridge_scan.update({"net": net, "step": i, "total": total})

        def on_found(item):
            # Докладываем сразу, а не в самом конце. Адрес в журнал не пишем:
            # его нельзя давать переписать руками.
            box = self.bridge_scan.setdefault("entries", [])
            if item not in box:
                box.append(item)
            self._logput(f"[*] Точка входа найдена (DC{item.get('dc', '?')}). "
                         f"Всего: {len(box)}.")

        self.bridge_scan.update({"running": True, "net": "", "step": 0,
                                 "total": 0, "entries": []})
        try:
            self._logput("[*] Ищу точку входа для встроенного моста…")
            found = tgbridge.find_entries(progress=progress,
                                          stop=self._bridge_stop, limit=3,
                                          on_found=on_found)
            self.bridge_scan["entries"] = found
            self.s["tg_entries"] = found
            settings_store.save(self.s)
            return found
        finally:
            self.bridge_scan["running"] = False

    def _scan_proxies(self) -> dict:
        """Шаг 2: уже запущенный на этом компьютере прокси-клиент."""
        self._logput("[*] Смотрю, нет ли уже запущенного прокси…")
        live: list = []

        def progress(done, total, item):
            # Каждая находка видна СРАЗУ. Раньше весь список появлялся одним
            # куском в конце, и до этого момента экран не менялся вовсе.
            live.append(item)
            self.tg_scan = {"best": next((f for f in live if not f.get("broken")), None),
                            "all": list(live), "clients": [],
                            "scanned": total, "alive": total, "running": True}
            if item.get("broken"):
                return
            self.tg_proxy = self.tg_proxy or item
            self._logput(f"[*] Нашёл: {item['title']} — {item['note']}.")

        res = tgproxy.scan(stop=self._bridge_stop, progress=progress)
        self.tg_scan = res
        self.tg_proxy = res.get("best")
        return res

    def _connect_worker(self):
        try:
            found = self._find_entries()
            if found:
                # адреса в журнал не пишем — чтобы их нельзя было вписать руками
                self._logput(f"[*] Найдено точек входа: {len(found)}. Поднимаю мост.")
                self.bridge_start()
                return
            if self._bridge_stop.is_set():
                self._logput("[*] Поиск остановлен.")
                return

            self._logput("[!] Своих точек входа нет — у провайдера закрыты все "
                         "адреса Telegram.")
            res = self._scan_proxies()
            if self._bridge_stop.is_set() and not res.get("best"):
                self._logput("[*] Поиск остановлен.")
                return
            best = res.get("best")
            if best:
                self._logput(f"[*] Найден {best['title']} — {best['note']}. "
                             f"Нажми «Настроить Telegram».")
            else:
                self._logput(f"[!] Рабочего прокси нет. Проверено пар "
                             f"адрес-порт: {res.get('scanned', 0)}, "
                             f"откликнулось {res.get('alive', 0)}.")
                socks4 = [f for f in res.get("all", ()) if f.get("kind") == "socks4"]
                if socks4:
                    self._logput("    Нашёлся SOCKS4 ("
                                 + ", ".join(f"{f['host']}:{f['port']}" for f in socks4)
                                 + "), но Telegram умеет только SOCKS5 и HTTP. "
                                   "Переключи клиент на SOCKS5.")
                if res.get("clients"):
                    self._logput("    Запущены: " + ", ".join(res["clients"])
                                 + " — включи в них локальный прокси "
                                   "(SOCKS5 на 127.0.0.1).")
                elif res.get("configured"):
                    # Клиент установлен и настроен, но выключен. Раньше об этом
                    # сказать было нечего: мы знали только про запущенные.
                    self._logput("    В настройках установленных клиентов "
                                 "записаны порты: "
                                 + ", ".join(str(x) for x in res["configured"][:6])
                                 + ". Похоже, клиент просто не запущен — включи его.")
        except Exception as exc:  # noqa: BLE001
            self._logput(f"[!] Подключение Telegram: {exc}")
        finally:
            self.bridge_scan["running"] = False
            with self._lock:
                self.tg_searching = False

    def bridge_start(self):
        entries = self.bridge_scan.get("entries") or []
        if not entries:
            self._logput("[!] Сначала найди точку входа.")
            return False
        if self.bridge and self.bridge.running:
            return True
        try:
            br = tgbridge.TgBridge(entries, port=tgbridge.DEFAULT_PORT,
                                   logger=self._logput)
            br.start()
            self.bridge = br
            self._logput(f"[*] Мост поднят. В Telegram: SOCKS5, 127.0.0.1, "
                         f"порт {tgbridge.DEFAULT_PORT}.")
            return True
        except Exception as exc:  # noqa: BLE001
            self._logput(f"[!] Мост не поднялся: {exc}")
            return False

    def bridge_stop(self):
        if self.bridge:
            self.bridge.stop()
            self.bridge = None
            self._logput("[*] Мост выключен.")
        return True

    def bridge_open(self):
        """Открыть ссылку tg:// на встроенный мост."""
        if not (self.bridge and self.bridge.running):
            self._logput("[!] Мост не запущен.")
            return False
        link = tgbridge.socks_link("127.0.0.1", tgbridge.DEFAULT_PORT)
        ok, how = tgproxy.open_link(link)
        # Настройки называем ВСЕГДА, а не только при ошибке: если окно выбора
        # приложения свернуть или закрыть не выбрав ничего, Telegram считает
        # ссылку отменённой и гасит прокси, а человек остаётся без подсказки.
        self._logput(f"    Вручную это: SOCKS5, 127.0.0.1, порт "
                     f"{tgbridge.DEFAULT_PORT} — Настройки → Продвинутые "
                     f"настройки → Тип соединения.")
        if ok:
            self._logput(f"[*] Отдал ссылку в {how} — подтверди в Telegram.")
            return True
        self._logput(f"[!] Не открылось ({how}).")
        return False

    def telegram_open(self, port=None):
        """Открыть ссылку tg://, чтобы Telegram сам предложил добавить прокси."""
        found = None
        entries = (self.tg_scan or {}).get("all") or []
        if port is not None:
            found = next((f for f in entries
                          if int(f.get("port", -1)) == int(port) and not f.get("broken")),
                         None)
        if found is None:
            found = self.tg_proxy
        if not found or found.get("broken"):
            self._logput("[!] Сначала найди прокси — нечего открывать.")
            return False
        kind = (found.get("kind") or "").upper() or "SOCKS5"
        manual = (f"    Вручную: {kind}, {found['host']}, порт {found['port']} — "
                  f"Настройки → Продвинутые настройки → Тип соединения.")
        link = tgproxy.link_for(found)
        if not link:
            # Ссылки для HTTP-прокси у Telegram нет вовсе. Отправить его как
            # SOCKS5 (так было раньше) — значит получить «прокси настроен
            # неверно и будет отключён» и потерять уже настроенный прокси.
            self._logput(f"[*] {found['title']} — добавляется только руками: "
                         f"ссылки tg:// для HTTP-прокси не существует.")
            self._logput(manual)
            return False
        ok, how = tgproxy.open_link(link)
        self._logput(manual)
        if ok:
            self._logput(f"[*] Отдал ссылку в {how} — подтверди добавление "
                         f"в Telegram.")
            return True
        self._logput(f"[!] Не удалось открыть ссылку ({how}).")
        return False

    def telegram_link(self, port=None):
        """Текст ссылки — чтобы можно было скопировать руками."""
        entries = (self.tg_scan or {}).get("all") or []
        found = next((f for f in entries
                      if port is not None and int(f.get("port", -1)) == int(port)
                      and not f.get("broken")), None) or self.tg_proxy
        return tgproxy.link_for(found) if found and not found.get("broken") else ""

    # старые имена — на случай, если где-то остался прежний вызов
    def find_telegram_proxy(self):
        return self.telegram_connect()

    def open_telegram_proxy(self):
        if not self.tg_scan:
            return self.telegram_connect()
        return self.telegram_open()

    # -- автостарт первого запуска ----------------------------------------
    def maybe_auto_config(self, skip_diag=False):   # noqa: D401
        # Диагностика идёт всегда: без неё непонятно, что вообще обходить, и
        # обход применялся бы к сервисам, которые и так работают.
        # skip_diag=True — её уже прогнал экран загрузки, второй раз не надо.
        if not skip_diag:
            self.run_diagnose()
        if not self.s.get("auto_config", True) or self.s.get("auto_tuned"):
            return
        if not is_admin():
            return
        # ждём вердикт — подбор без него перебирал бы и то, что не заблокировано
        for _ in range(60):
            if not self.diag_running:
                break
            time.sleep(0.5)
        self._logput("[*] Первый запуск — подбираю обход под твою сеть…")
        self.run_autotune(by_user=False)

    # -- сторож: сервис отвалился -> перепобрать обход ----------------------
    def _anticheat_tick(self):
        """Уступить дорогу античиту: пока идёт игра, драйвер должен быть выгружен.

        Обход работает через WinDivert — тот же способ, которым пользуются читы,
        поэтому античит видит загруженный драйвер и не пускает в игру. Прятаться
        от него мы не будем: это его работа. Вместо этого на время игры обход
        выключается сам, а после выхода — включается обратно.
        """
        if not self.s.get("pause_on_anticheat", False):
            return
        try:
            found = anticheat.running()
        except Exception:
            return
        self.ac_found = found

        if found:
            with self._lock:
                busy = self.state in ("starting", "running")
            if busy and not self.ac_paused:
                self.ac_paused = True
                self._logput(f"[*] Запущен античит ({', '.join(found)}) — выключаю "
                             f"обход, чтобы не мешать игре. Включу обратно сам.")
                self.stop()
            return

        if self.ac_paused:
            self.ac_paused = False
            with self._lock:
                idle = self.state == "idle" and not self.auto["running"]
            if idle:
                self._logput("[*] Античит закрылся — возвращаю обход.")
                self.start()

    def _watch_worker(self):
        while not self._watch_stop.wait(5.0):
            try:
                self._anticheat_tick()
            except Exception as exc:  # noqa: BLE001
                self._logput(f"[!] Проверка античита: {exc}")
            try:
                self._harvest_hosts()
            except Exception as exc:  # noqa: BLE001
                self._logput(f"[!] Сбор имён: {exc}")
            try:
                self._conflict_tick()
            except Exception as exc:  # noqa: BLE001
                self._logput(f"[!] Проверка соседей: {exc}")
            if time.monotonic() - self._watch_at < WATCH_PERIOD:
                continue
            self._watch_at = time.monotonic()
            try:
                self._watch_tick()
            except Exception as exc:  # noqa: BLE001
                self._logput(f"[!] Сторож: {exc}")

    def _harvest_hosts(self):
        """Забрать у движка имена серверов, которые он видел вживую."""
        eng = self.engine
        seen = getattr(eng, "seen_hosts", None) if eng else None
        if not seen:
            return
        box = self.s.setdefault("seen_hosts", {})
        stamp = self.s.setdefault("seen_hosts_at", {})
        changed = False
        for gid, hosts in seen.items():
            keep = list(hosts)[-4:]        # четырёх свежих хватает
            if box.get(gid) != keep:
                box[gid] = keep
                stamp[gid] = int(time.time())
                changed = True
        if changed:
            settings_store.save(self.s)

    def _probe_extra(self) -> dict:
        """Запомненные имена — но только те, что ещё живы.

        Имена вроде rr5---sn-q4fl6nzy.googlevideo.com выдаются под сессию и
        через сутки перестают существовать. А проверка кандидата требует, чтобы
        прошли ВСЕ хосты группы — значит одно протухшее имя навсегда лишает
        группу возможности подобрать хоть что-нибудь. Отсеиваем по DNS: имя,
        которое не разрешается, мертво. Блокировка на это не влияет — режут по
        SNI уже после разрешения имени, DNS при этом отвечает как обычно.
        """
        box = self.s.get("seen_hosts") or {}
        if not box:
            return {}
        stamp = self.s.get("seen_hosts_at") or {}
        now = int(time.time())
        out, drop = {}, False
        for gid, hosts in box.items():
            # Протухшие по времени выбрасываем не глядя. Проверить их иначе
            # нечем: rr4---sn-....googlevideo.com разрешается через
            # *.googlevideo.com и после того, как сессия давно кончилась, —
            # то есть DNS про это молчит.
            age = now - int(stamp.get(gid, 0) or 0)
            if age > SEEN_HOSTS_TTL:
                if hosts:
                    box[gid] = []
                    drop = True
                continue
            live = [h for h in list(hosts)[:6] if self._resolves(h)]
            if live != list(hosts):
                box[gid] = live
                drop = True
            if live:
                out[gid] = live[:3]
        if drop:
            settings_store.save(self.s)
        return out

    @staticmethod
    def _resolves(host: str) -> bool:
        try:
            socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            return True
        except Exception:                            # noqa: BLE001
            return False

    def _conflict_tick(self):
        """Кто ещё занял драйвер или увёл трафик в туннель."""
        now = conflicts.found()
        was = {c["title"] for c in self.conflicts}
        self.conflicts = now
        for c in now:
            if c["title"] in was:
                continue                       # про каждого говорим один раз
            if c["level"] == "blocker":
                self._logput(f"[!] Запущен {c['title']} — он держит тот же драйвер "
                             f"WinDivert. Пока он работает, обход не включится.")
            else:
                self._logput(f"[*] Запущен {c['title']}: трафик идёт через туннель, "
                             f"обход ему уже не нужен.")

    def _watch_tick(self):
        with self._lock:
            if self.state != "running" or not self.s["watchdog"] or self.auto["running"]:
                return
        groups = self._enabled_groups()
        if not groups:
            return

        res = autotune.test_probes(groups, 4)
        bad = [g for g in groups if not res.get(g)]
        for g in groups:
            if g not in bad:
                self._watch_strikes.pop(g, None)
        if not bad:
            return

        # Защита от ложной тревоги: если не отвечает и контрольный хост, это
        # интернет лёг, а не блокировка. Перепобор тут только навредит.
        if not autotune.internet_alive(4):
            self._logput("[*] Сторож: сеть не отвечает целиком — это не блокировка.")
            return

        now = time.monotonic()
        retune = []
        for g in bad:
            n = self._watch_strikes.get(g, 0) + 1
            self._watch_strikes[g] = n
            if n < WATCH_STRIKES:
                self._logput(f"[*] Сторож: {services.title(g)} не открылся "
                             f"({n}/{WATCH_STRIKES}) — жду ещё одну проверку.")
                continue
            if now - self._watch_last.get(g, -1e9) < WATCH_COOLDOWN:
                continue          # не долбим: не чаще раза в час на группу
            retune.append(g)
        if retune:
            self._retune(retune)

    def _retune(self, groups):
        names = ", ".join(services.title(g) for g in groups)
        with self._lock:
            if self.auto["running"] or self.state != "running":
                return
            self._auto_gen += 1
            gen = self._auto_gen
            self._auto_stop.clear()
            self.auto.clear()
            self.auto.update({
                "running": True, "progress": 0.02, "eta": 0, "best": None,
                "status": f"Перепобираю обход для {names}…",
                "matrix": [{"id": g, "title": services.title(g),
                            "icon": services.GROUPS[g]["icon"],
                            "state": "wait", "label": ""} for g in groups],
            })
        self._logput(f"[*] Сторож: {names} перестал открываться — перепобираю обход.")

        # подбор поднимает свой движок, поэтому текущий нужно закрыть
        self.stop()
        for _ in range(80):
            with self._lock:
                if self.state == "idle":
                    break
            time.sleep(0.1)
        try:
            self._tune_groups(gen, groups)
        finally:
            with self._lock:
                if gen == self._auto_gen:
                    self.auto["running"] = False
            now = time.monotonic()
            for g in groups:
                self._watch_last[g] = now
                self._watch_strikes.pop(g, None)
            self.start()
            self._logput("[*] Сторож: обход снова включён.")


# ── трей ──────────────────────────────────────────────────────────────────
_tray = None
# окно нужно кнопке «скрыть всё»: Api сам его не создаёт
_window = None


def _make_tray(api: "Api", window):
    if pystray is None or Image is None:
        return None
    icon_path = os.path.join(res_base(), "assets", "icon.ico")
    try:
        image = Image.open(icon_path)
    except Exception:
        image = Image.new("RGBA", (64, 64), (79, 140, 255, 255))

    def show(_i=None, _item=None):
        try:
            window.show()
        except Exception:
            pass

    def toggle(_i=None, _item=None):
        api.toggle()

    def quit_app(_i=None, _item=None):
        api.shutdown()          # закрыть WinDivert по-человечески, а не смертью процесса
        try:
            _tray.stop()
        except Exception:
            pass
        for w in list(webview.windows):
            try:
                w.destroy()
            except Exception:
                pass
        os._exit(0)

    menu = pystray.Menu(
        pystray.MenuItem("Открыть RuFreedom", show, default=True),
        pystray.MenuItem("Вкл/выкл обход", toggle),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Выход", quit_app),
    )
    return pystray.Icon("RuFreedom", image, "RuFreedom — обход DPI", menu)


def main() -> int:
    if os.name != "nt":
        print("RuFreedom работает только на Windows (нужен WinDivert).")
        return 1

    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Anthropic.RuFreedom")
    except Exception:
        pass

    api = Api()
    # Открываемся достаточно большими, чтобы весь интерфейс был виден сразу,
    # но не больше рабочей области экрана — иначе часть окна уедет за край.
    win_w, win_h = 1280, 900
    sw = sh = 0
    try:
        user32 = ctypes.windll.user32
        user32.SetProcessDPIAware()
        sw, sh = user32.GetSystemMetrics(0), user32.GetSystemMetrics(1)
        win_w = max(1000, min(win_w, int(sw * 0.92)))
        win_h = max(760, min(win_h, int(sh * 0.90)))
    except Exception:
        pass

    def centre(w, h):
        """Левый верхний угол, чтобы окно встало серединой экрана.

        Без явных координат положение выбирает Windows, и заставка вылезает
        где придётся -- чаще всего в левом верхнем углу.
        """
        if not sw or not sh:
            return None, None
        return max(0, (sw - w) // 2), max(0, (sh - h) // 2)

    def page(name):
        """Адрес страницы в правильном виде: file:///C:/путь/....

        Голый windows-путь отдавать нельзя: pywebview клеит его как
        file:// + путь с обратными слэшами, и диск попадает на место имени
        хоста. Страница откроется, но базовый адрес будет битым, а с ним и
        любые относительные ссылки внутри неё.
        """
        return pathlib.Path(res_base(), "web", name).as_uri()

    html = page("index.html")
    splash_file = os.path.join(res_base(), "web", "splash.html")
    splash_html = page("splash.html") if os.path.isfile(splash_file) else ""

    # Экран загрузки. Он поднимается первым и держит человека в курсе, пока
    # идёт подготовка; главное окно до готовности скрыто, чтобы никто не
    # смотрел на пустой интерфейс и не жал кнопки, которым ещё нечем работать.
    splash = None
    if splash_html:
        try:
            sx, sy = centre(460, 250)
            splash = webview.create_window(
                "RuFreedom", url=splash_html,
                width=460, height=250, x=sx, y=sy,
                frameless=True, easy_drag=True,
                on_top=True, resizable=False, background_color="#0a0e17",
            )
        except Exception:
            splash = None

    mx, my = centre(win_w, win_h)
    window = webview.create_window(
        "RuFreedom", url=html, js_api=api,
        width=win_w, height=win_h, x=mx, y=my, min_size=(1000, 760),
        background_color="#0a0e17", hidden=splash is not None,
    )

    globals()["_window"] = window

    # закрытие окна — прячем в трей (если он есть), а не выходим
    global _tray
    _tray = _make_tray(api, window)

    def on_closing():
        if _tray is not None:
            try:
                window.hide()
            except Exception:
                pass
            return False   # отменяем закрытие — уходим в трей
        return True

    try:
        window.events.closing += on_closing
    except Exception:
        pass

    def say(pct, text=None):
        """Двинуть полосу загрузки и подписать, чем заняты сейчас."""
        if splash is None:
            return
        arg = "%.1f" % float(pct)
        if text:
            arg += ", " + json.dumps(text, ensure_ascii=False)
        try:
            splash.evaluate_js("window.rzProgress && window.rzProgress(%s)" % arg)
        except Exception:
            pass

    def prepare():
        """Подготовка до показа главного окна.

        Держим здесь только то, что реально быстро: права, настройки и
        диагностику. Подбор обхода сюда не входит — он идёт до двух минут,
        и человек должен видеть его в самом окне, а не в заставке.
        """
        say(8, "Проверяю права администратора…")
        if not is_admin():
            api._logput("[!] Нет прав администратора — обход работать не будет.")
        say(18, "Читаю настройки…")
        time.sleep(0.25)
        say(28, "Смотрю, что у тебя заблокировано…")

        # Проверка хостов -- самая длинная часть, и она единственная умеет
        # честно сказать, сколько сделано. Растягиваем её на 28..92%.
        def on_probe(done, total):
            if total <= 0:
                return
            say(28 + 64.0 * done / total,
                f"Проверяю сервисы: {done} из {total}")

        api.run_diagnose(progress=on_probe)
        # ждём вердикт, но не вечно: сеть может лежать целиком
        for _ in range(80):          # 40 секунд потолок
            if not api.diag_running:
                break
            time.sleep(0.5)
        else:
            api._logput("[!] Проверка затянулась — открываю окно, "
                        "она продолжится сама.")
        say(100, "Готово")
        time.sleep(0.45)             # даём полосе доехать до конца

    # прошлый exe, отодвинутый при обновлении, больше не нужен
    update.cleanup_old()

    # Папки прошлых запусков, которые не удалось удалить при выходе: их держал
    # загруженный драйвер. Каждая весит десятки мегабайт, и без уборки они
    # копятся неделями.
    try:
        gone, freed = tempclean.sweep()
        if gone:
            api._logput(f"[*] Убрано папок от прошлых запусков: {gone} "
                        f"({freed // (1024 * 1024)} МБ).")
    except Exception:                                 # noqa: BLE001
        pass

    def on_start():
        if _tray is not None:
            threading.Thread(target=_tray.run, daemon=True).start()
        diag_done = False
        try:
            if splash is not None:
                time.sleep(0.6)      # даём заставке отрисоваться
                prepare()
                diag_done = True
        except Exception as exc:      # noqa: BLE001
            api._logput(f"[!] Подготовка: {exc}")
        finally:
            # Что бы ни случилось, окно обязано открыться: иначе человек
            # остаётся с одной заставкой и без программы.
            try:
                window.show()
            except Exception:
                pass
            if splash is not None:
                try:
                    splash.destroy()
                except Exception:
                    pass
        if not diag_done:
            time.sleep(1.2)
        api.check_update()
        api.maybe_auto_config(skip_diag=diag_done)

    webview.start(on_start)
    return 0


if __name__ == "__main__":
    sys.exit(main())
