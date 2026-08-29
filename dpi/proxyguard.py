"""
Не трогать трафик прокси-клиентов.

Зачем. Обход отбирает пакеты по порту (443 и прочие TLS) и решает, что с ними
делать, по имени сайта из ClientHello. Прокси-клиент — NekoBox, v2rayN, Xray,
Clash — ходит к своему серверу ровно так же: TLS на 443. И маскируется он
обычно под какой-нибудь безобидный домен: gcore, cloudfront, cdn77. Все три
у нас в списке группы «Сети доставки».

Дальше очевидное: мы разрезаем и десинхронизируем ClientHello самого прокси.
Его туннель рвётся, а ломается при этом то, что через туннель шло, — и
виноватым выглядит прокси. Ровно отсюда «прокси работает, а через пару секунд
Telegram пишет, что он настроен неверно, и выключает его». И отсюда же «при
переключении чата ещё быстрее»: новый чат — новые картинки — новые соединения
клиента наружу, и каждое из них мы портим заново.

Помогать обходом такому трафику бессмысленно в принципе: он уже зашифрован и
уже идёт в обход. Трогать его можно только во вред.

Как отличаем: спрашиваем у системы, какие соединения принадлежат процессам
прокси-клиентов, и складываем адреса их серверов. Пакеты на эти адреса
проходят мимо обхода нетронутыми.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import socket
import struct
from typing import Dict, List, Set

# Процессы, чей трафик наружу трогать нельзя. Список тот же по духу, что и в
# conflicts.py, но задача другая: там мы предупреждаем человека, здесь —
# защищаем их соединения от собственного обхода.
CLIENT_NAMES = (
    "nekobox", "nekoray", "throne",
    "v2ray", "xray", "sing-box", "singbox",
    "clash", "mihomo", "hiddify", "flclash",
    "shadowsocks", "outline", "netch",
    "warp-svc", "cloudflarewarp",
    "amnezia", "amneziawg", "awg",
    "wireguard", "openvpn", "tun2socks",
    "psiphon", "tor", "obfs4proxy",
    "nordvpn", "expressvpn", "surfshark", "protonvpn", "windscribe",
)

# Короткие имена сверяем ЦЕЛИКОМ. Иначе «tor» находится внутри
# aggregatorhost.exe — обычной службы Windows, и её адреса попадают под
# защиту вместе с настоящими. Тот же подвох был в conflicts.py.
EXACT_NAMES = {"tor", "awg", "xray", "clash", "netch", "outline", "singbox"}

MIB_TCP_STATE_ESTAB = 5


class _Row(ctypes.Structure):
    _fields_ = [("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD),
                ("dwLocalPort", wt.DWORD), ("dwRemoteAddr", wt.DWORD),
                ("dwRemotePort", wt.DWORD), ("dwOwningPid", wt.DWORD)]


def _process_names() -> Dict[int, str]:
    """pid -> имя процесса в нижнем регистре."""
    try:
        from .conflicts import TH32CS_SNAPPROCESS, _Entry
    except Exception:                                 # noqa: BLE001
        return {}
    out: Dict[int, str] = {}
    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return out
    try:
        e = _Entry()
        e.dwSize = ctypes.sizeof(_Entry)
        ok = k32.Process32First(snap, ctypes.byref(e))
        while ok:
            out[e.th32ProcessID] = e.szExeFile.decode("cp1251", "replace").lower()
            ok = k32.Process32Next(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


def client_pids(names: Dict[int, str] | None = None) -> Set[int]:
    """Кто из запущенного — прокси-клиент."""
    procs = names if names is not None else _process_names()
    out = set()
    for pid, name in procs.items():
        stem = name[:-4] if name.endswith(".exe") else name
        if any(_hit(stem, key) for key in CLIENT_NAMES):
            out.add(pid)
    return out


def _hit(stem: str, key: str) -> bool:
    """Совпало ли имя процесса с ключом."""
    if key in EXACT_NAMES:
        return stem == key or stem.startswith(key + "-") or stem.startswith(key + "_")
    return key in stem


def guarded_addrs() -> Set[str]:
    """Адреса серверов, к которым подключены прокси-клиенты.

    Только установленные соединения: слушающие сокеты и полузакрытые нам
    неинтересны, а лишний адрес в списке — это кусок трафика, оставшийся без
    обхода.
    """
    if os.name != "nt":
        return set()
    pids = client_pids()
    if not pids:
        return set()
    try:
        iphlp = ctypes.windll.iphlpapi
        size = wt.DWORD(0)
        TCP_TABLE_OWNER_PID_ALL = 5
        iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, 2,
                                  TCP_TABLE_OWNER_PID_ALL, 0)
        if not size.value:
            return set()
        buf = ctypes.create_string_buffer(size.value)
        if iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, 2,
                                     TCP_TABLE_OWNER_PID_ALL, 0) != 0:
            return set()
        count = ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0]
        rows = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(wt.DWORD)),
                           ctypes.POINTER(_Row))
        out: Set[str] = set()
        for i in range(count):
            r = rows[i]
            if r.dwOwningPid not in pids:
                continue
            if r.dwState != MIB_TCP_STATE_ESTAB:
                continue
            addr = socket.inet_ntoa(struct.pack("<L", r.dwRemoteAddr))
            if addr in ("0.0.0.0", "127.0.0.1"):
                continue                              # своё же, локальное
            out.add(addr)
        return out
    except Exception:                                 # noqa: BLE001
        return set()


def summary(addrs: Set[str]) -> str:
    """Строка для журнала. Пусто — значит защищать нечего."""
    if not addrs:
        return ""
    shown = sorted(addrs)[:3]
    tail = "" if len(addrs) <= 3 else f" и ещё {len(addrs) - 3}"
    return ("Не трогаю соединения прокси-клиентов: "
            + ", ".join(shown) + tail
            + ". Их трафик уже зашифрован, и обход может его только сломать.")


def client_titles() -> List[str]:
    """Какие клиенты сейчас запущены — для объяснения человеку."""
    procs = _process_names()
    out: List[str] = []
    for pid in client_pids(procs):
        name = procs.get(pid, "")
        stem = name[:-4] if name.endswith(".exe") else name
        if stem and stem not in out:
            out.append(stem)
    return sorted(out)
