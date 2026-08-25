#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Самопроверка обхода: включает движок и честно меряет, что пробивает.

Зачем: из интерфейса не видно, работает ли обход на самом деле — там только
«Обход запущен». Этот скрипт запускает движок сам, по очереди пробует стратегии
и после каждой делает настоящее TLS-рукопожатие к заблокированным сайтам.
В конце — таблица: что сработало, а что нет.

Запускать ОТ АДМИНИСТРАТОРА (нужен драйвер WinDivert):
    python selftest.py
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
import time

# скрипт лежит в tools/, а пакет dpi -- на уровень выше
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Консоль Windows по умолчанию не в UTF-8, и русский вывод превращается
# в кашу. Просим Python писать в UTF-8 независимо от кодовой страницы.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from dpi import autotune, diagnose            # noqa: E402
from dpi.config import Config                 # noqa: E402
from dpi.engine import Engine                 # noqa: E402

# что проверяем: по два хоста на сервис, чтобы не поверить случайности
ALL_TARGETS = [
    ("YouTube",      "www.youtube.com"),
    ("YouTube API",  "youtubei.googleapis.com"),
    ("Discord",      "discord.com"),
    ("Discord шлюз", "gateway.discord.gg"),
]
# `selftest.py youtube` — гонять перебор только по YouTube: он один остался
# непробитым, и ждать проверку Discord каждый раз незачем
_only = sys.argv[1].lower() if len(sys.argv) > 1 else ""
if _only.startswith("you") or _only.startswith("ют"):
    TARGETS = [t for t in ALL_TARGETS if "YouTube" in t[0]]
elif _only.startswith("dis") or _only.startswith("дис"):
    TARGETS = [t for t in ALL_TARGETS if "Discord" in t[0]]
else:
    TARGETS = ALL_TARGETS

# сколько раз проверять каждый хост: блокировка мигает, одиночный успех
# ещё ничего не значит
TRIES = 3


def pause() -> None:
    """Не дать окну закрыться сразу. Молча пропускаем, если ввода нет."""
    try:
        input(chr(10) + "Enter — выход...")
    except (EOFError, KeyboardInterrupt):
        pass


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def measure(label: str) -> dict:
    """{имя: сколько из TRIES рукопожатий прошло}."""
    out = {}
    for name, host in TARGETS:
        ok = sum(1 for _ in range(TRIES) if autotune.test_host(host, 5))
        out[name] = ok
    total = sum(out.values())
    top = len(TARGETS) * TRIES
    print(f"  {label:34} " + "  ".join(f"{n}:{v}/{TRIES}" for n, v in out.items())
          + f"   ИТОГО {total}/{top}")
    return out


def run_with(profile, label: str) -> dict:
    """Поднять движок с профилем, померить, погасить."""
    cfg = Config()
    cfg.host_groups = {h: "test" for _, h in TARGETS}
    cfg.hosts = set(cfg.host_groups)
    cfg.profiles = {"test": profile}
    eng = Engine(cfg, logger=lambda *_: None)
    th = threading.Thread(target=eng.run, daemon=True)
    th.start()
    eng.ready.wait(timeout=6)
    if not eng.running:
        print(f"  {label:34} ДРАЙВЕР НЕ ОТКРЫЛСЯ: {eng.error}")
        return {}
    time.sleep(0.3)
    try:
        return measure(label)
    finally:
        eng.stop()
        th.join(timeout=5)
        time.sleep(0.3)


def main() -> int:
    print("=" * 78)
    print("  Самопроверка обхода RuFreedom")
    print("=" * 78)

    if os.name != "nt":
        print("Только для Windows.")
        return 1
    if not is_admin():
        print("\n[!] НУЖНЫ ПРАВА АДМИНИСТРАТОРА.")
        print("    Закрой это окно, открой командную строку от администратора")
        print("    и запусти оттуда:  python selftest.py")
        pause()
        return 1

    print("\nСначала — что происходит БЕЗ обхода (эталон):\n")
    base = measure("без обхода")
    if sum(base.values()) == len(TARGETS) * TRIES:
        print("\n[*] Всё и так открывается. Обход сейчас не нужен.")
        pause()
        return 0

    print("\nТеперь перебираю стратегии. Каждая: включить -> померить -> выключить.\n")
    results = []
    for combo in autotune.CANDIDATES:
        prof = autotune.candidate_to_profile(combo, quic_mode="drop")
        got = run_with(prof, combo["label"])
        if got:
            results.append((sum(got.values()), combo["label"], got))
        # если пробило всё — дальше можно не искать
        if got and sum(got.values()) == len(TARGETS) * TRIES:
            print("\n[*] Полное попадание — дальше не перебираю.")
            break

    print("\n" + "=" * 78)
    if not results:
        print("  Ни одна стратегия не отработала — драйвер не открылся ни разу.")
        print("  Проверь, что запущено от администратора и что не мешает")
        print("  антивирус. Ещё вариант — залипшая служба: sc stop windivert")
        pause()
        return 1

    results.sort(reverse=True)
    best_score, best_label, best_detail = results[0]
    top = len(TARGETS) * TRIES
    print(f"  ЛУЧШАЯ СТРАТЕГИЯ: {best_label}  ({best_score}/{top})")
    print("  Подробно:", "  ".join(f"{n}:{v}/{TRIES}" for n, v in best_detail.items()))
    print(f"  Для сравнения без обхода: {sum(base.values())}/{top}")
    print()
    print("  Тройка лучших:")
    for score, label, _ in results[:3]:
        print(f"    {score:3}/{top}   {label}")
    if best_score <= sum(base.values()):
        print()
        print("  [!] Ни одна стратегия не дала выигрыша по сравнению с «без обхода».")
        print("      Значит дело не в подборе — либо провайдер режет иначе,")
        print("      либо пакеты не доходят до движка. Пришли этот вывод мне.")
    print("=" * 78)
    pause()
    return 0


if __name__ == "__main__":
    sys.exit(main())
