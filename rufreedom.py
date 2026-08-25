#!/usr/bin/env python3
"""
RuFreedom 0.0.1 — локальный обход DPI-блокировок для доступа к игровым
серверам и сервисам (по подобию zapret / GoodbyeDPI).

Запуск (от имени администратора):
    python rufreedom.py
    python rufreedom.py --strategy fake --hostlist config/hostlist.txt

Внимание: требует прав администратора и драйвера WinDivert (ставится вместе
с pydivert). Инструмент предназначен для обхода цензуры/блокировок — никакого
перехвата чужого трафика он не делает, только меняет ВАШИ исходящие пакеты.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import sys

from dpi import __version__, config
from dpi.config import Config
from dpi.engine import Engine


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def parse_args() -> argparse.Namespace:
    base = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(
        prog="rufreedom",
        description="RuFreedom — локальный обход DPI-блокировок.",
    )
    p.add_argument("--config", default=os.path.join(base, "config", "rufreedom.ini"),
                   help="путь к ini-конфигу")
    p.add_argument("--strategy", choices=list(config.STRATEGIES),
                   help="техника десинхронизации (переопределяет конфиг)")
    p.add_argument("--fooling", choices=list(config.FOOLINGS),
                   help="обман фальшивого сегмента (для fake-стратегий)")
    p.add_argument("--split-mode", choices=list(config.SPLITS),
                   help="где резать пакет (posN — абсолютное смещение)")
    p.add_argument("--ports", help="список портов через запятую, напр. 80,443")
    p.add_argument("--quic", choices=list(config.QUIC_MODES),
                   help="обработка QUIC/UDP-443")
    p.add_argument("--hostlist", help="путь к списку хостов (пусто = весь трафик)")
    p.add_argument("--fake-ttl", type=int, help="TTL фальшивого пакета (strategy=fake)")
    p.add_argument("--fake-count", type=int, help="сколько подделок слать подряд (1-8)")
    p.add_argument("--seg-count", type=int, help="сегментов в multi-режимах (2-6)")
    p.add_argument("--fake-sni", help="имя сайта в подделке (по умолчанию www.google.com)")
    p.add_argument("--all", action="store_true",
                   help="применять обход ко всему трафику (игнорировать hostlist)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    print(f"RuFreedom {__version__}\n")

    if os.name != "nt":
        print("[!] Этот инструмент работает только на Windows (нужен WinDivert).")
        return 1

    if not is_admin():
        print("[!] Нужны права администратора. Запусти start.bat или консоль от админа.")
        return 1

    cfg = Config.load(args.config)
    if args.strategy:
        cfg.strategy = args.strategy
    if args.fooling:
        cfg.fooling = args.fooling
    if args.split_mode:
        cfg.split_mode = args.split_mode
    if args.ports:
        cfg.ports = [int(x) for x in args.ports.split(",") if x.strip()]
    if args.quic:
        cfg.quic_mode = args.quic
    if args.fake_ttl is not None:
        cfg.fake_ttl = args.fake_ttl
    if args.fake_count is not None:
        cfg.fake_count = args.fake_count
    if args.seg_count is not None:
        cfg.seg_count = args.seg_count
    if args.fake_sni:
        cfg.fake_sni = args.fake_sni
    if args.hostlist:
        cfg.hostlist_path = args.hostlist
    if args.all:
        cfg.hostlist_path = ""

    engine = Engine(cfg)
    try:
        engine.run()
    except RuntimeError as exc:
        print(f"[!] {exc}")
        return 1
    except PermissionError:
        print("[!] Отказано в доступе. Запусти от имени администратора.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
