"""
Временная папка сборки и драйвер, который её держит.

Откуда берётся окно «Failed to remove temporary directory: ...\\_MEI95242».

Программа собрана одним файлом. При запуске она распаковывает себя в
`%TEMP%\\_MEIxxxxx`, а при выходе эту папку удаляет. Внутри неё лежит и
драйвер WinDivert — и когда обход включается, Windows регистрирует службу,
указывающую ПРЯМО ТУДА:

    ImagePath: \\??\\C:\\Users\\...\\Temp\\_MEI231802\\pydivert\\windivert_dll\\WinDivert64.sys

Пока драйвер загружен, система держит этот файл открытым, и папка не
удаляется. Отсюда и предупреждение. Само по себе оно безобидно — программа
к тому моменту уже закрыта, — но папки копятся: каждая весит десятки
мегабайт, и через неделю их набирается с десяток.

Здесь две вещи:

  * `wait_driver_gone` — подождать перед выходом, пока WinDivert выгрузится
    сам. Обычно хватает долей секунды, и папка удаляется как надо.
  * `sweep` — прибрать за прошлыми запусками. Трогаем только СВОИ папки: с
    нашей разметкой внутри, не занятые, и заведомо не ту, на которую сейчас
    показывает служба.

Останавливать драйвер силой мы не станем: тот же WinDivert используют zapret
и GoodbyeDPI, и выдернуть его из-под них было бы свинством.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import shutil
import sys
import time
from typing import List, Tuple

SERVICE_NAME = "WinDivert"

# Права только на чтение состояния: менять службу мы не собираемся.
SC_MANAGER_CONNECT = 0x0001
SERVICE_QUERY_STATUS = 0x0004
ERROR_SERVICE_DOES_NOT_EXIST = 1060

SERVICE_STOPPED = 1

# По этим файлам папка опознаётся как наша. Просто «_MEI*» мало: такие папки
# делает любая программа, собранная тем же способом.
MARKERS = (
    os.path.join("pydivert", "windivert_dll", "WinDivert64.sys"),
    os.path.join("web", "index.html"),
)


class _Status(ctypes.Structure):
    _fields_ = [("dwServiceType", wt.DWORD),
                ("dwCurrentState", wt.DWORD),
                ("dwControlsAccepted", wt.DWORD),
                ("dwWin32ExitCode", wt.DWORD),
                ("dwServiceSpecificExitCode", wt.DWORD),
                ("dwCheckPoint", wt.DWORD),
                ("dwWaitHint", wt.DWORD)]


def driver_state() -> str:
    """"gone" — службы нет; "stopped"; "running"; "unknown" — спросить не вышло."""
    if os.name != "nt":
        return "gone"
    try:
        adv = ctypes.windll.advapi32
        # Дескрипторы служб — указатели. Без явного restype ctypes считает их
        # int и на 64 битах обрезает старшую половину: дескриптор получается
        # битым, и дальше всё молча не работает.
        adv.OpenSCManagerW.restype = ctypes.c_void_p
        adv.OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
        adv.OpenServiceW.restype = ctypes.c_void_p
        adv.OpenServiceW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, wt.DWORD]
        adv.CloseServiceHandle.argtypes = [ctypes.c_void_p]
        adv.QueryServiceStatus.argtypes = [ctypes.c_void_p, ctypes.POINTER(_Status)]
    except Exception:                                 # noqa: BLE001
        return "unknown"
    scm = adv.OpenSCManagerW(None, None, SC_MANAGER_CONNECT)
    if not scm:
        return "unknown"
    try:
        svc = adv.OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS)
        if not svc:
            return ("gone" if ctypes.GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST
                    else "unknown")
        try:
            st = _Status()
            if not adv.QueryServiceStatus(svc, ctypes.byref(st)):
                return "unknown"
            return "stopped" if st.dwCurrentState == SERVICE_STOPPED else "running"
        finally:
            adv.CloseServiceHandle(svc)
    finally:
        adv.CloseServiceHandle(scm)


def wait_driver_gone(timeout: float = 3.0) -> bool:
    """Подождать, пока WinDivert выгрузится. True — дождались.

    Вызывается перед самым выходом. Без этого мы успеваем закрыться раньше,
    чем драйвер отпустит свой файл, и распакованная папка остаётся навсегда.
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        state = driver_state()
        if state in ("gone", "stopped"):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def driver_dir() -> str:
    """Папка, на которую сейчас показывает служба драйвера. Её не трогаем."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\\" + SERVICE_NAME)
        try:
            path, _ = winreg.QueryValueEx(key, "ImagePath")
        finally:
            winreg.CloseKey(key)
    except Exception:                                 # noqa: BLE001
        return ""
    text = str(path or "").replace("\\??\\", "")
    marker = os.sep + "_MEI"
    i = text.find(marker)
    if i < 0:
        return ""
    j = text.find(os.sep, i + 1)
    return text[:j] if j > 0 else text


def _is_ours(path: str) -> bool:
    return all(os.path.exists(os.path.join(path, m)) for m in MARKERS)


def stale_dirs() -> List[str]:
    """Папки прошлых запусков, которые остались лежать."""
    if os.name != "nt":
        return []
    temp = os.environ.get("TEMP") or os.environ.get("TMP") or ""
    if not temp or not os.path.isdir(temp):
        return []
    mine = os.path.normcase(getattr(sys, "_MEIPASS", "") or "")
    busy = os.path.normcase(driver_dir())
    out = []
    try:
        names = os.listdir(temp)
    except OSError:
        return []
    for name in names:
        if not name.startswith("_MEI"):
            continue
        path = os.path.join(temp, name)
        low = os.path.normcase(path)
        if low == mine or (busy and low == busy):
            continue                                  # своя текущая или занятая
        if not os.path.isdir(path) or not _is_ours(path):
            continue
        out.append(path)
    return out


def sweep(limit: int = 20) -> Tuple[int, int]:
    """Убрать оставшиеся папки. (сколько убрано, сколько освободилось байт).

    Занятые папки просто пропускаем: если удалить не дают, значит их кто-то
    ещё держит, и настаивать незачем.
    """
    removed = freed = 0
    for path in stale_dirs()[:limit]:
        size = 0
        try:
            for root, _dirs, files in os.walk(path):
                for name in files:
                    try:
                        size += os.path.getsize(os.path.join(root, name))
                    except OSError:
                        pass
        except OSError:
            pass
        try:
            shutil.rmtree(path)
        except OSError:
            continue                                  # держат — не настаиваем
        removed += 1
        freed += size
    return removed, freed
