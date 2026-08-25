"""
Уживаемся с античитами.

Обход DPI работает через WinDivert — драйвер, который перехватывает и
переписывает сетевые пакеты. Ровно этим же занимаются читы, поэтому античиты
(EasyAntiCheat, BattlEye, Vanguard, FACEIT) реагируют на загруженный драйвер и
не пускают в игру. Это их работа, и обходить её мы не будем и не станем: тут
нечего чинить со стороны обхода.

Правильное решение — не мешать: пока игра с античитом запущена, обход
выключается и драйвер выгружается, а после выхода из игры включается обратно.
Этот модуль умеет только одно — увидеть, что античит запущен.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
from typing import List

# Процессы античитов. Совпадение проверяется по началу имени без расширения,
# поэтому EasyAntiCheat_EOS.exe и EasyAntiCheat.exe ловятся одной записью.
#
# Сюда попадают ТОЛЬКО те процессы, которые живут вместе с игрой. Например
# vgtray.exe (значок Vanguard в трее) висит в системе постоянно — если ставить
# паузу по нему, обход не включится никогда; ловим vgc, который поднимается
# уже под игру.
ANTICHEATS = {
    "easyanticheat": "EasyAntiCheat",
    "beservice": "BattlEye",
    "bedaisy": "BattlEye",
    "vgc": "Vanguard",
    "faceitservice": "FACEIT",
    "esea": "ESEA",
    "ricochet": "Ricochet",
    "gameguard": "GameGuard",
    "gepblocker": "nProtect",
}

TH32CS_SNAPPROCESS = 0x00000002
MAX_PATH = 260


class _PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]


def _process_names() -> List[str]:
    """Имена запущенных процессов. Без сторонних библиотек и без tasklist."""
    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return []
    out: List[str] = []
    entry = _PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(_PROCESSENTRY32)
    try:
        if not k32.Process32First(snap, ctypes.byref(entry)):
            return []
        while True:
            out.append(entry.szExeFile.decode("latin-1", "ignore").lower())
            if not k32.Process32Next(snap, ctypes.byref(entry)):
                break
    finally:
        k32.CloseHandle(snap)
    return out


def running() -> List[str]:
    """Названия античитов, работающих прямо сейчас (без повторов)."""
    found: List[str] = []
    for name in _process_names():
        stem = name.rsplit(".", 1)[0]
        for key, title in ANTICHEATS.items():
            if stem.startswith(key) and title not in found:
                found.append(title)
    return found
