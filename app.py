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
import sys
import threading
import time
import webbrowser

import webview

from dpi import (anticheat, autotune, config as config_mod, diagnose, services,
                 settings_store, tgbridge, tgproxy)
from dpi import autostart, update
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


def res_base() -> str:
    """Папка с ресурсами: _MEIPASS в собранном exe, иначе рядом со скриптом."""
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


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
            "voice_fake": self.s["voice_fake"],
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
        cfg.udp_ranges = {gid: services.udp_range(gid) for gid in enabled
                          if services.udp_range(gid)}
        return cfg

    def _hosts(self) -> set:
        if self.s["all_traffic"]:
            return set()
        return services.domains_for(self._enabled_groups())

    # -- автоподбор --------------------------------------------------------
    def run_autotune(self, only=None, by_user=True):
        with self._lock:
            if self.auto["running"] or self.diag_running:
                self._logput("[!] Дождись окончания текущей проверки.")
                return False
            if self.state != "idle":
                self._logput("[!] Сначала выключи обход, потом подбирай.")
                return False
            if not is_admin():
                self._logput("[!] Автоподбор требует прав администратора.")
                return False
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
            self._auto_thread = threading.Thread(target=self._auto_worker,
                                                 args=(gen, list(targets), by_user),
                                                 daemon=True, name="rz-auto")
            self._auto_thread.start()
        return True

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

    def _auto_worker(self, gen, targets, by_user=True):
        won = 0
        try:
            won = self._tune_groups(gen, targets)
        except Exception as exc:  # noqa: BLE001
            self.auto["status"] = "Ошибка автоподбора"
            self._logput(f"[!] Автоподбор: {exc}")
        finally:
            with self._lock:
                # отставший воркер не должен снимать флаг с более нового запуска
                if gen == self._auto_gen:
                    self.auto["running"] = False
        if won and gen == self._auto_gen:
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

        # полный план: сперва проверенные комбинации, затем сетка добора.
        # Без сетки подбор упирался в список и сдавался — а youtubei
        # берётся только ею.
        combos = autotune.all_candidates()
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
            if not pending:
                break
            self.auto["progress"] = max(0.03, i / len(combos))
            self.auto["eta"] = autotune.eta_seconds(len(pending), i)
            self.auto["status"] = f"Проверяю: {combo['label']} ({i + 1}/{len(combos)})"
            for gid in pending:
                self._mx(gid, "test")

            ok, opened = self._test_candidate(combo, pending)
            if not opened:
                open_fails += 1
                # проблема с драйвером, а не со стратегией: две минуты молчаливых
                # неудач тут никому не помогут
                if open_fails >= 2:
                    self.auto["status"] = "Не удалось открыть драйвер WinDivert"
                    self._logput("[!] WinDivert не открывается — подбор прерван. "
                                 "Запусти от администратора и проверь антивирус.")
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
            ok2, opened2 = self._test_candidate(combo, maybe, tries=3)

            hit, flaky = [], []
            for gid in maybe:
                if opened2 and not ok2.get(gid):
                    flaky.append(services.title(gid))
                    self._mx(gid, "wait")
                    continue
                won[gid] = combo
                pending.remove(gid)
                self._mx(gid, "ok", combo["label"])
                hit.append(services.title(gid))
            if hit:
                self._logput(f"[*] {combo['label']} -> пробило: {', '.join(hit)}")
            if flaky:
                self._logput(f"[~] {combo['label']} -> у {', '.join(flaky)} "
                             "не подтвердилось, ищу дальше.")

        for gid in pending:
            self._mx(gid, "fail", "не пробило ничем")

        # 2. сохранить: своей группе — свой профиль
        for gid, combo in won.items():
            prof = autotune.candidate_to_profile(
                combo, quic_mode=self.s["quic_mode"],
                udp_fake=bool(services.udp_range(gid)) and self.s["voice_fake"])
            self.s["profiles"][gid] = prof.to_dict()

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
        else:
            self.auto["status"] = "Ничего не пробило — попробуй вручную"
            self._logput("[!] Автоподбор ничего не пробил.")

        self.s["auto_tuned"] = True
        settings_store.save(self.s)
        self.auto["progress"] = 1.0
        self.auto["eta"] = 0
        return len(won)

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

    def _test_candidate(self, combo, groups, tries=2):
        """Прогнать одну комбинацию на проверочных хостах групп.

        Возвращает ({группа: пробило}, открылся ли драйвер). Второе важно
        отдельно: если WinDivert не открылся, все False означают не «не
        пробило», а «проверка не состоялась».
        """
        prof = autotune.candidate_to_profile(combo, quic_mode=self.s["quic_mode"])
        cfg = Config()
        cfg.host_groups = {host: gid for gid, host in autotune.probe_targets(groups)}
        cfg.hosts = set(cfg.host_groups)
        cfg.profiles = {gid: prof for gid in groups}
        eng = Engine(cfg, logger=lambda *_: None)
        th = threading.Thread(target=eng.run, daemon=True, name="rz-probe")
        th.start()
        eng.ready.wait(timeout=5)         # взводится и при успехе, и при провале
        opened = eng.running
        try:
            if not opened:
                return {}, False
            time.sleep(0.2)
            return autotune.test_probes(groups, 4, tries), True
        finally:
            eng.stop()
            th.join(timeout=4)
            time.sleep(0.2)

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

        # Новая копия уже запущена. Гасим драйвер и уходим, иначе две копии
        # какое-то время держали бы WinDivert одновременно.
        try:
            self.shutdown()
        except Exception:                            # noqa: BLE001
            pass
        os._exit(0)

    def dismiss_update(self):
        """«Позже»: убрать окно требования до следующего запуска."""
        self.upd_later = True
        return True

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

        self.bridge_scan.update({"running": True, "net": "", "step": 0, "total": 0})
        try:
            self._logput("[*] Ищу точку входа для встроенного моста…")
            found = tgbridge.find_entries(progress=progress,
                                          stop=self._bridge_stop, limit=3)
            self.bridge_scan["entries"] = found
            self.s["tg_entries"] = found
            settings_store.save(self.s)
            return found
        finally:
            self.bridge_scan["running"] = False

    def _scan_proxies(self) -> dict:
        """Шаг 2: уже запущенный на этом компьютере прокси-клиент."""
        self._logput("[*] Смотрю, нет ли уже запущенного прокси…")
        res = tgproxy.scan(stop=self._bridge_stop)
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
                self._logput(f"[!] Рабочего прокси нет. Проверено портов: "
                             f"{res.get('scanned', 0)}, откликнулось "
                             f"{res.get('alive', 0)}.")
                if res.get("clients"):
                    self._logput("    Запущены: " + ", ".join(res["clients"])
                                 + " — включи в них локальный прокси "
                                   "(SOCKS5 на 127.0.0.1).")
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
        try:
            os.startfile(link)          # noqa: S606 — ссылка tg://, не файл
            self._logput(f"[*] Открыл {link} — подтверди в Telegram.")
            return True
        except Exception as exc:  # noqa: BLE001
            self._logput(f"[!] Не открылось ({exc}). Настрой вручную: SOCKS5, "
                         f"127.0.0.1, порт {tgbridge.DEFAULT_PORT}.")
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
        link = tgproxy.link_for(found)
        try:
            os.startfile(link)          # noqa: S606 — это ссылка tg://, не файл
            self._logput(f"[*] Открыл {link} — подтверди добавление в Telegram.")
            return True
        except Exception as exc:  # noqa: BLE001
            self._logput(f"[!] Не удалось открыть ссылку ({exc}). "
                         f"Настрой вручную: {found['kind'] or 'SOCKS5'}, "
                         f"{found['host']}, порт {found['port']}.")
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

    def retune_group(self, gid):
        """Перепобрать обход для одной группы (кнопка на карточке)."""
        if gid not in services.GROUPS:
            return False
        return self.run_autotune(only=[gid])

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
            if time.monotonic() - self._watch_at < WATCH_PERIOD:
                continue
            self._watch_at = time.monotonic()
            try:
                self._watch_tick()
            except Exception as exc:  # noqa: BLE001
                self._logput(f"[!] Сторож: {exc}")

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
