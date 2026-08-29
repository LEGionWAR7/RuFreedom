"""Конфигурация RuFreedom: значения по умолчанию + чтение rufreedom.ini."""

from __future__ import annotations

import configparser
import os
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Set

# --- допустимые значения (единый источник правды для GUI, CLI и автоподбора) --

STRATEGIES = ("split", "disorder", "fake", "fakedisorder",
              "multisplit", "multidisorder", "fakedsplit", "fakeddisorder")

# Простое разрезание помогает только против DPI, который смотрит на каждый
# TCP-сегмент отдельно. Тот, что собирает поток обратно, режь как хочешь —
# он всё равно увидит целое имя. Против него работают только техники, которые
# ЛОМАЮТ саму пересборку:
#   fakedsplit / fakeddisorder — подделка вставляется МЕЖДУ кусками, с номером
#     второго куска. DPI склеивает первый кусок с подделкой и получает битый
#     ClientHello; сервер подделку выбрасывает (её убивает fooling) и склеивает
#     настоящие куски.
#   seqovl — первый кусок уходит с номером на N назад и с N байтами мусора
#     впереди. Сервер по правилам TCP отрезает всё, что раньше начала потока,
#     и получает свои данные в целости, а DPI подставляет мусор в начало.

# Где резать пакет.
#   first-char / mid-host / host-start / host-end — относительно имени сайта;
#   pos1 / pos2 / pos3 — абсолютное смещение от начала пакета. Разрез на 2-м
#   байте рвёт сам заголовок TLS-записи, и многие DPI после этого вообще не
#   опознают в потоке TLS. Именно этот приём (у zapret он зовётся split-pos=2)
#   чаще всего и пробивает YouTube с Discord — раньше его тут не было.
SPLITS = ("first-char", "mid-host", "host-start", "host-end",
          "pos1", "pos2", "pos3", "pos4", "pos5", "pos8", "pos12",
          "host+1", "host+2", "host+3",
          # Разрез по домену второго уровня: для www.youtube.com это «youtube».
          # Именно так режет zapret по умолчанию, и на части провайдеров это
          # единственное, что срабатывает: имя рвётся там, где DPI ищет его
          # целиком, а не в начале строки.
          "sld", "midsld", "endsld")

# Имена-приманки для подделок. Смысл в том, чтобы назваться сайтом, который
# DPI пропускает не глядя. Нейтральные www.google.com и ya.ru работают не
# везде; web.vk.me держат в белых списках почти все российские провайдеры,
# поэтому он часто пробивает там, где гугл уже нет.
FAKE_SNIS = ("www.google.com", "web.vk.me", "ya.ru", "www.microsoft.com")

# Чем «убить» фальшивый сегмент, чтобы его увидел DPI, но не увидел сервер.
#   ttl       — пакет не доживает до сервера (нужно угадать число хопов);
#   badsum    — неверная контрольная сумма (часть провайдеров её чинит сама);
#   badseq    — номер последовательности отмотан далеко назад, сервер считает
#               пакет устаревшим и молча выбрасывает. Не зависит ни от числа
#               хопов, ни от оборудования провайдера — самый живучий вариант;
#   ttlbadsum — низкий TTL и битая сумма разом;
#   none      — без обмана (годится только для split/disorder).
FOOLINGS = ("ttl", "badsum", "badseq", "ttlbadsum", "none")

QUIC_MODES = ("drop", "fake", "ipfrag", "off")

DEFAULT_FAKE_SNI = "www.google.com"


@dataclass
class Profile:
    """Набор техник обхода для одной группы сервисов."""

    strategy: str = "fakeddisorder"
    split_mode: str = "pos2"
    fooling: str = "badseq"
    fake_ttl: int = 4
    # сколько фальшивых пакетов слать подряд: часть DPI запоминает последний
    # увиденный сегмент, часть — первый, повтор закрывает оба случая
    fake_count: int = 2
    # на сколько сегментов резать в multi-режимах
    seg_count: int = 3
    # имя сайта в подделке (обычный незаблокированный домен)
    fake_sni: str = DEFAULT_FAKE_SNI
    # Перекрытие номеров: сколько байт подставить перед первым куском
    # (0 = выключено). Ломает пересборку у DPI, сервера не касается.
    # Заполняется НЕ мусором, а целым ClientHello на имя fake_sni: DPI
    # разбирает его и считает, что соединение идёт на разрешённый сайт.
    # Типовые рабочие значения — 568 и 681 (столько занимает такой ClientHello).
    seqovl: int = 0
    # Обнулять поле Identification в IP-заголовке. У zapret это
    # `--ip-id=zero`, и в его конфиге этот ключ стоит РОВНО для списка
    # Google — то есть для YouTube. Часть DPI связывает пакеты одного
    # потока по этому полю, и одинаковый ноль сбивает такую сборку.
    ip_id_zero: bool = False
    quic_mode: str = "drop"
    # десинхронизация обычного UDP (голос Discord), а не QUIC
    udp_fake: bool = False
    # TTL голосовой подделки. 0 — не трогать вовсе (так у zapret, и так по
    # умолчанию): подделка это заведомо чужой для голоса протокол, сервер
    # отбрасывает её сам, а зажатый TTL мешает её увидеть тому единственному,
    # ради кого она посылается, — оборудованию провайдера.
    voice_ttl: int = 0
    # Сколько раз повторить голосовую подделку. У zapret шесть: одиночную
    # DPI успевает проглядеть.
    voice_repeats: int = 6

    def normalized(self) -> "Profile":
        p = replace(self)
        if p.strategy not in STRATEGIES:
            p.strategy = "fakeddisorder"
        if p.split_mode not in SPLITS:
            p.split_mode = "pos2"
        if p.fooling not in FOOLINGS:
            p.fooling = "badseq"
        if p.quic_mode not in QUIC_MODES:
            p.quic_mode = "drop"
        p.fake_ttl = max(1, min(64, int(p.fake_ttl)))
        p.fake_count = max(1, min(8, int(p.fake_count)))
        p.seg_count = max(2, min(6, int(p.seg_count)))
        p.seqovl = max(0, min(1400, int(p.seqovl)))
        p.voice_ttl = max(0, min(64, int(p.voice_ttl)))
        p.voice_repeats = max(1, min(16, int(p.voice_repeats)))
        p.ip_id_zero = bool(p.ip_id_zero)
        # Подделка с fooling=none дошла бы до сервера как настоящий ClientHello
        # и сломала бы рукопожатие сильнее любой блокировки.
        if p.uses_fake and p.fooling == "none":
            p.fooling = "badseq"
        return p

    @property
    def uses_fake(self) -> bool:
        return self.strategy in ("fake", "fakedisorder", "fakedsplit", "fakeddisorder")

    @property
    def fake_between(self) -> bool:
        """Подделка идёт МЕЖДУ кусками, а не перед ними."""
        return self.strategy in ("fakedsplit", "fakeddisorder")

    @property
    def reorders(self) -> bool:
        return self.strategy in ("disorder", "multidisorder", "fakedisorder",
                                 "fakeddisorder")

    @property
    def segments(self) -> int:
        if self.strategy in ("multisplit", "multidisorder"):
            return max(2, min(6, int(self.seg_count)))
        return 2

    def label(self) -> str:
        bits = [self.strategy, self.fooling]
        if self.fooling in ("ttl", "ttlbadsum"):
            bits[-1] = f"{self.fooling}{self.fake_ttl}"
        bits.append(self.split_mode)
        if self.uses_fake and self.fake_count > 1:
            bits.append(f"x{self.fake_count}")
        if self.seqovl:
            bits.append(f"ovl{self.seqovl}")
        if self.ip_id_zero:
            bits.append("id0")
        return " / ".join(bits)

    def to_dict(self) -> dict:
        return {"strategy": self.strategy, "split_mode": self.split_mode,
                "fooling": self.fooling, "fake_ttl": self.fake_ttl,
                "fake_count": self.fake_count, "seg_count": self.seg_count,
                "fake_sni": self.fake_sni, "seqovl": self.seqovl,
                "ip_id_zero": self.ip_id_zero,
                "quic_mode": self.quic_mode, "udp_fake": self.udp_fake,
                "voice_ttl": self.voice_ttl, "voice_repeats": self.voice_repeats}

    @classmethod
    def from_dict(cls, d) -> "Profile":
        if not isinstance(d, dict):
            return cls().normalized()
        known = {f: d[f] for f in cls.__dataclass_fields__ if f in d}
        try:
            return cls(**known).normalized()
        except (TypeError, ValueError):
            return cls().normalized()


@dataclass
class Config:
    # Порты, на которых перехватываем исходящий трафик. Кроме 80 и 443 сюда
    # входят «запасные» TLS-порты Cloudflare: через них ходит discord.media
    # (голос и стримы), и без них половина Discord остаётся без обхода.
    ports: List[int] = field(
        default_factory=lambda: [80, 443, 2053, 2083, 2087, 2096, 8443])
    # --- глобальные значения: их читают CLI (rufreedom.py) и rufreedom.ini,
    # и они же становятся профилем для групп, которым свой не назначен
    strategy: str = "multisplit"
    split_mode: str = "pos1"
    fooling: str = "none"
    fake_ttl: int = 4
    fake_count: int = 2
    seg_count: int = 2
    fake_sni: str = DEFAULT_FAKE_SNI
    seqovl: int = 568
    quic_mode: str = "drop"
    # путь к списку хостов (пусто = применять ко всему трафику)
    hostlist_path: str = ""
    # явный набор хостов (имеет приоритет над файлом; используется GUI)
    hosts: Set[str] = field(default_factory=set)
    # домены, которые не трогаем никогда (банки, госуслуги, и то, что и так
    # открывается) — сильнее любого совпадения, включая режим «весь трафик»
    exclude: Set[str] = field(default_factory=set)
    # --- посервисный обход
    # {домен: id группы} — по нему движок понимает, чей это трафик
    host_groups: Dict[str, str] = field(default_factory=dict)
    # {id группы: Profile} — своя стратегия на группу
    profiles: Dict[str, "Profile"] = field(default_factory=dict)
    # {id группы: (порт_от, порт_до)} — не-QUIC UDP (голос Discord)
    udp_ranges: Dict[str, tuple] = field(default_factory=dict)
    # Адреса, к которым подключены прокси-клиенты. Их трафик обход не трогает
    # ни при каких настройках: он уже зашифрован и уже идёт в обход, а
    # разрезанный ClientHello ломает туннель. Список живой, обновляется на ходу.
    skip_addrs: set = field(default_factory=set)

    def default_profile(self) -> Profile:
        """Профиль из глобальных значений — для групп без своего."""
        return Profile(strategy=self.strategy, split_mode=self.split_mode,
                       fooling=self.fooling, fake_ttl=self.fake_ttl,
                       fake_count=self.fake_count, seg_count=self.seg_count,
                       fake_sni=self.fake_sni, seqovl=self.seqovl,
                       quic_mode=self.quic_mode).normalized()

    def profile_for(self, group: Optional[str]) -> Profile:
        if group:
            p = self.profiles.get(group)
            if p is not None:
                return p
        return self.default_profile()

    def active_profiles(self) -> List[Profile]:
        """Все профили, участвующие в работе — для сборки фильтра WinDivert."""
        out = list(self.profiles.values())
        out.append(self.default_profile())
        return out

    @classmethod
    def load(cls, path: str) -> "Config":
        cfg = cls()
        if not path or not os.path.isfile(path):
            return cfg

        parser = configparser.ConfigParser()
        parser.read(path, encoding="utf-8")
        if not parser.has_section("rufreedom"):
            return cfg
        s = parser["rufreedom"]

        if "ports" in s:
            cfg.ports = [int(p.strip()) for p in s["ports"].split(",") if p.strip()]
        cfg.strategy = s.get("strategy", cfg.strategy).strip().lower()
        cfg.split_mode = s.get("split_mode", cfg.split_mode).strip().lower()
        cfg.fooling = s.get("fooling", cfg.fooling).strip().lower()
        cfg.fake_ttl = s.getint("fake_ttl", cfg.fake_ttl)
        cfg.fake_count = s.getint("fake_count", cfg.fake_count)
        cfg.seg_count = s.getint("seg_count", cfg.seg_count)
        cfg.seqovl = s.getint("seqovl", cfg.seqovl)
        cfg.fake_sni = s.get("fake_sni", cfg.fake_sni).strip()
        cfg.quic_mode = s.get("quic_mode", cfg.quic_mode).strip().lower()
        cfg.hostlist_path = s.get("hostlist_path", cfg.hostlist_path).strip()

        # относительный путь к hostlist — от папки конфига
        if cfg.hostlist_path and not os.path.isabs(cfg.hostlist_path):
            cfg.hostlist_path = os.path.join(os.path.dirname(path), cfg.hostlist_path)
        return cfg
