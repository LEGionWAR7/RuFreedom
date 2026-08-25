"""
Автозапуск RuFreedom при входе в Windows.

Используется Планировщик задач (schtasks) с правами «наивысшие» — чтобы
приложение стартовало уже с правами администратора (иначе обход не сможет
работать без ручного повышения). Создание/удаление задачи требует прав
администратора (они есть, когда приложение запущено через start.bat).
"""

from __future__ import annotations

import os
import subprocess
import sys

TASK_NAME = "RuFreedom Autostart"
# Так задача называлась до переименования. Её надо снимать, иначе после
# обновления в Планировщике останутся ДВЕ задачи и программа будет
# стартовать дважды.
LEGACY_TASK_NAME = "RusZapret Autostart"
_NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW — не мигать консолью


def _launch_cmd() -> str:
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    # запускаем app.py через pythonw (без окна консоли)
    py = sys.executable
    pyw = os.path.join(os.path.dirname(py), "pythonw.exe")
    exe = pyw if os.path.isfile(pyw) else py
    app = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app.py"))
    return f'"{exe}" "{app}"'


class _Result:
    def __init__(self, code: int, out: str = "", err: str = "") -> None:
        self.returncode = code
        self.stdout = out
        self.stderr = err


def _run(args) -> "_Result":
    # берём вывод байтами и декодируем с errors='ignore': schtasks на
    # русской Windows печатает в OEM-кодировке, а text=True падает на ней.
    try:
        p = subprocess.run(args, capture_output=True, creationflags=_NO_WINDOW)
        out = (p.stdout or b"").decode("utf-8", "ignore")
        err = (p.stderr or b"").decode("utf-8", "ignore")
        return _Result(p.returncode, out, err)
    except Exception as exc:  # schtasks недоступен и т.п.
        return _Result(1, "", str(exc))


def is_enabled() -> bool:
    """Задача есть И указывает на текущий исполняемый файл.

    Проверяем не только наличие задачи, но и её командную строку: задача,
    созданная прежней версией, может ссылаться на файл, которого больше нет
    (раньше это был gui.py). Такую считаем выключенной, чтобы интерфейс
    предложил включить автозапуск заново и задача перезаписалась.
    """
    r = _run(["schtasks", "/query", "/tn", TASK_NAME, "/fo", "LIST", "/v"])
    if r.returncode != 0:
        return False

    want = _launch_cmd().replace('"', "").strip().lower()
    for line in (r.stdout or "").splitlines():
        # имя поля зависит от языка Windows, поэтому смотрим на обе версии
        low = line.lower()
        if "task to run" in low or "задача для выполнения" in low:
            got = line.split(":", 1)[-1].replace('"', "").strip().lower()
            if not got:
                continue
            return want in got or got in want
    # поле не нашлось (другая локаль) — не придираемся, задача есть
    return True


def _drop_legacy() -> None:
    """Снять задачу под старым именем (молча: её может и не быть)."""
    _run(["schtasks", "/delete", "/tn", LEGACY_TASK_NAME, "/f"])


def enable() -> tuple[bool, str]:
    _drop_legacy()
    r = _run(["schtasks", "/create", "/tn", TASK_NAME, "/tr", _launch_cmd(),
              "/sc", "onlogon", "/rl", "highest", "/f"])
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def disable() -> tuple[bool, str]:
    _drop_legacy()
    r = _run(["schtasks", "/delete", "/tn", TASK_NAME, "/f"])
    return r.returncode == 0, (r.stderr or r.stdout).strip()
