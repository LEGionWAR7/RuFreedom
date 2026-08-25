#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Прицельный перебор под ОДИН упрямый хост.

Обычный автоподбор гоняет заранее заданный список комбинаций. Когда хост не
берётся ни одной, нужен не список, а сетка: перебрать число сегментов, точку
разреза и перекрытие во всех сочетаниях и посмотреть, что сработает.

Так был найден обход для www.youtube.com: сработало только multidisorder на
три сегмента с разрезом в начале имени — ни одна другая из 31 комбинации.
Для youtubei.googleapis.com (через него грузятся Shorts и лента) подбираем
тем же способом.

Запускать ОТ АДМИНИСТРАТОРА:
    python sweep.py                          # по умолчанию — API YouTube
    python sweep.py rr1.googlevideo.com      # или любой свой хост
"""

from __future__ import annotations

import ctypes
import itertools
import os
import sys
import threading
import time

# скрипт лежит в tools/, а пакет dpi -- на уровень выше
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from dpi import autotune              # noqa: E402
from dpi.config import Config, Profile  # noqa: E402
from dpi.engine import Engine         # noqa: E402

HOST = sys.argv[1] if len(sys.argv) > 1 else "youtubei.googleapis.com"

# Сетка вокруг того, что уже показало себя: multi-режимы с разной нарезкой.
# Отдельно добавлено перекрытие — оно взяло Discord.
STRATEGIES = ["multidisorder", "multisplit"]
SEGMENTS = [3, 4, 5, 6]
SPLITS = ["host-start", "first-char", "mid-host", "host-end", "pos1", "pos3"]
# Перекрытие в разведку не берём: для обоих хостов YouTube оно провалилось во
# всех семи проверенных вариантах (0/6). Discord им берётся, YouTube — нет.
OVERLAPS = [0]

# на разведке хватает двух попыток, победителя потом перепроверим четырьмя
TRIES_SCAN = 2
TRIES_CONFIRM = 4


def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def measure(tries: int) -> int:
    return sum(1 for _ in range(tries) if autotune.test_host(HOST, 5))


def run_with(prof: Profile, tries: int) -> int:
    cfg = Config()
    cfg.host_groups = {HOST: "test"}
    cfg.hosts = {HOST}
    cfg.profiles = {"test": prof}
    eng = Engine(cfg, logger=lambda *_: None)
    th = threading.Thread(target=eng.run, daemon=True)
    th.start()
    eng.ready.wait(timeout=6)
    if not eng.running:
        return -1
    time.sleep(0.3)
    try:
        return measure(tries)
    finally:
        eng.stop()
        th.join(timeout=5)
        time.sleep(0.25)


def main() -> int:
    print("=" * 78)
    print(f"  Прицельный перебор для: {HOST}")
    print("=" * 78)
    if not is_admin():
        print("\n[!] Нужны права администратора.")
        try:
            input("\nEnter — выход...")
        except Exception:
            pass
        return 1

    base = measure(TRIES_CONFIRM)
    print(f"\nБез обхода: {base}/{TRIES_CONFIRM}")
    if base == TRIES_CONFIRM:
        print("Хост и так открывается — перебирать нечего.")
        try:
            input("\nEnter — выход...")
        except Exception:
            pass
        return 0

    grid = list(itertools.product(STRATEGIES, SEGMENTS, SPLITS, OVERLAPS))
    print(f"Комбинаций в сетке: {len(grid)}. Примерно {len(grid) * 7 // 60} мин.\n")

    hits = []
    for i, (strat, segs, split, ovl) in enumerate(grid, 1):
        prof = Profile(strategy=strat, seg_count=segs, split_mode=split,
                       fooling="none", seqovl=ovl,
                       fake_sni="www.google.com").normalized()
        got = run_with(prof, TRIES_SCAN)
        mark = "  " if got <= 0 else "ЕСТЬ"
        if got < 0:
            print(f"  [{i:3}/{len(grid)}] {strat:14} x{segs} {split:11} ovl{ovl:<4} "
                  f"драйвер не открылся")
            continue
        print(f"  [{i:3}/{len(grid)}] {strat:14} x{segs} {split:11} ovl{ovl:<4} "
              f"{got}/{TRIES_SCAN} {mark}")
        if got == TRIES_SCAN:
            hits.append((strat, segs, split, ovl))
            if len(hits) >= 3:
                print("\n  Найдено три рабочих — дальше не ищу.")
                break

    print("\n" + "=" * 78)
    if not hits:
        print("  Ничего не сработало. Этот хост режут не по имени в ClientHello —")
        print("  скорее всего, по чему-то ещё. Пришли этот вывод мне.")
        try:
            input("\nEnter — выход...")
        except Exception:
            pass
        return 1

    print("  Перепроверяю найденное более длинной серией:\n")
    best = None
    for strat, segs, split, ovl in hits:
        prof = Profile(strategy=strat, seg_count=segs, split_mode=split,
                       fooling="none", seqovl=ovl,
                       fake_sni="www.google.com").normalized()
        got = run_with(prof, TRIES_CONFIRM)
        print(f"    {strat:14} x{segs} {split:11} ovl{ovl:<4} -> {got}/{TRIES_CONFIRM}")
        if best is None or got > best[0]:
            best = (got, strat, segs, split, ovl)

    print()
    if best and best[0] > base:
        got, strat, segs, split, ovl = best
        print(f"  ПОБЕДИТЕЛЬ: {strat} x{segs}, разрез {split}, перекрытие {ovl}"
              f"   ({got}/{TRIES_CONFIRM}, без обхода было {base}/{TRIES_CONFIRM})")
        print("\n  Строка для меня:")
        print(f'    {{"strategy":"{strat}","seg_count":{segs},'
              f'"split_mode":"{split}","seqovl":{ovl},"fooling":"none"}}')
    else:
        print("  Устойчивого выигрыша нет — совпадения были случайными.")
    print("=" * 78)
    try:
        input("\nEnter — выход...")
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
