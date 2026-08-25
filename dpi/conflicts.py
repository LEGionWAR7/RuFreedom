"""
Кто ещё на этом компьютере лезет в тот же трафик.

Зачем: у RuFreedom две беды, обе выглядят как «программа не работает», и обе
на самом деле про соседей.

1. **Драйвер занят.** zapret, GoodbyeDPI, ByeDPI и подобные работают через тот
   же WinDivert. Двое одновременно его не поделят: кто первый открыл, тот и
   владеет, второму — отказ. Подбор при этом обрывается на пустом месте.

2. **Трафик уходит мимо.** VPN вроде Amnezia, WireGuard или WARP поднимает
   свой сетевой адаптер и уводит в него ВЕСЬ трафик. Наши пакеты до провайдера
   в исходном виде уже не доходят, обходить нечего — но и вреда нет, просто
   работа впустую.

Разница важна: первое надо закрывать, второе — просто знать. Поэтому у каждой
находки есть уровень, а не общее «обнаружен конфликт».
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
from typing import Dict, List

# Уровни: blocker — мешает работать, tunnel — трафик идёт мимо нас.
PROGRAMS: Dict[str, Dict] = {
    # --- те, кто дерётся за WinDivert ---
    "winws": {"title": "zapret", "level": "blocker"},
    "goodbyedpi": {"title": "GoodbyeDPI", "level": "blocker"},
    "ciadpi": {"title": "ByeDPI", "level": "blocker"},
    "byedpi": {"title": "ByeDPI", "level": "blocker"},
    "spoofdpi": {"title": "SpoofDPI", "level": "blocker"},
    "powertunnel": {"title": "PowerTunnel", "level": "blocker"},
    "zapret": {"title": "zapret", "level": "blocker"},
    "windivert": {"title": "программа с драйвером WinDivert", "level": "blocker"},
    "greenTunnel": {"title": "Green Tunnel", "level": "blocker"},

    # --- те, кто уводит трафик в туннель ---
    # Порядок ВАЖЕН: побеждает первое совпадение, поэтому частное идёт
    # раньше общего. Иначе amneziawg-service опознался бы просто как Amnezia.
    "amneziawg": {"title": "AmneziaWG", "level": "tunnel"},
    "amneziavpn": {"title": "Amnezia VPN", "level": "tunnel"},
    "amnezia": {"title": "Amnezia VPN", "level": "tunnel"},
    "awg": {"title": "AmneziaWG", "level": "tunnel"},
    "wireguard": {"title": "WireGuard", "level": "tunnel"},
    "openvpn": {"title": "OpenVPN", "level": "tunnel"},
    "outline": {"title": "Outline", "level": "tunnel"},
    "warp-svc": {"title": "Cloudflare WARP", "level": "tunnel"},
    "cloudflarewarp": {"title": "Cloudflare WARP", "level": "tunnel"},
    "hiddify": {"title": "Hiddify", "level": "tunnel"},
    "nekobox": {"title": "NekoBox", "level": "tunnel"},
    "nekoray": {"title": "Nekoray", "level": "tunnel"},
    "v2rayn": {"title": "v2rayN", "level": "tunnel"},
    "xray": {"title": "Xray", "level": "tunnel"},
    "sing-box": {"title": "sing-box", "level": "tunnel"},
    "clash": {"title": "Clash", "level": "tunnel"},
    "mihomo": {"title": "Mihomo", "level": "tunnel"},
    "protonvpn": {"title": "Proton VPN", "level": "tunnel"},
    "windscribe": {"title": "Windscribe", "level": "tunnel"},
    "nordvpn": {"title": "NordVPN", "level": "tunnel"},
    "expressvpn": {"title": "ExpressVPN", "level": "tunnel"},
    "surfshark": {"title": "Surfshark", "level": "tunnel"},
    "tunnelbear": {"title": "TunnelBear", "level": "tunnel"},
    "psiphon": {"title": "Psiphon", "level": "tunnel"},
    "tor": {"title": "Tor", "level": "tunnel"},
    "hola": {"title": "Hola VPN", "level": "tunnel"},
    "browsec": {"title": "Browsec", "level": "tunnel"},
    "planetvpn": {"title": "Planet VPN", "level": "tunnel"},
}

# Эти ключи сверяем ЦЕЛИКОМ, а не как подстроку: «tor» иначе находится
# внутри explorer, а «clash» — внутри clashroyale-launcher.
_EXACT = {"tor", "clash", "xray", "awg", "hola"}

TH32CS_SNAPPROCESS = 0x00000002


class _Entry(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * 260)]


def process_names() -> List[str]:
    """Имена всех запущенных процессов, в нижнем регистре и без .exe."""
    if os.name != "nt":
        return []
    out: List[str] = []
    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return []
    try:
        e = _Entry()
        e.dwSize = ctypes.sizeof(_Entry)
        ok = k32.Process32First(snap, ctypes.byref(e))
        while ok:
            name = e.szExeFile.decode("cp1251", "replace").lower()
            if name.endswith(".exe"):
                name = name[:-4]
            out.append(name)
            ok = k32.Process32Next(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


def _hit(proc: str, key: str) -> bool:
    """Совпало ли имя процесса с ключом."""
    if key in _EXACT:
        return proc == key or proc.startswith(key + "-") or proc.startswith(key + "_")
    return key in proc


def found(names: List[str] | None = None) -> List[Dict]:
    """Что из соседей сейчас запущено. Каждый пункт — один раз."""
    procs = names if names is not None else process_names()
    seen: Dict[str, Dict] = {}
    for proc in procs:
        for key, meta in PROGRAMS.items():
            if not _hit(proc, key):
                continue
            # Первое совпадение и есть ответ. Без этого GoodbyeDPI попадал
            # в список ДВАЖДЫ: его имя содержит в себе и «byedpi».
            title = meta["title"]
            if title not in seen:
                seen[title] = {"title": title, "level": meta["level"], "proc": proc}
            break
    # сначала то, что мешает работать
    return sorted(seen.values(), key=lambda d: (d["level"] != "blocker", d["title"]))


def summary(items: List[Dict]) -> str:
    """Одна строка для интерфейса. Пусто — значит соседей нет."""
    if not items:
        return ""
    block = [i["title"] for i in items if i["level"] == "blocker"]
    tun = [i["title"] for i in items if i["level"] == "tunnel"]
    if block:
        return (", ".join(block) + " занимает тот же драйвер — пока он работает, "
                "обход не запустится. Закрой его.")
    return (", ".join(tun) + ": весь трафик идёт через туннель, "
            "и обход ему уже не нужен.")
