"""
Журнал изменений, который лежит ВНУТРИ программы.

Зачем отдельный файл, если есть релизы на GitHub: у релиза описание может
быть пустым (так и было у всех выпусков до 1.3.0 — теги стояли, а что в них
изменилось, не написано нигде), а интернета у человека может не быть вовсе.
Журнал в настройках должен открываться в любом случае, поэтому источник
правды здесь, а GitHub только дополняет: оттуда берутся дата и ссылка.

Формат разбираемого файла:

    ## 1.3.0 — 2026-08-26
    текст до следующего заголовка

Тире — любое: короткое, длинное или «--». Префикс «v» у версии допустим.
"""

from __future__ import annotations

import os
import re
import sys
from collections import OrderedDict
from typing import Dict

NAME = "CHANGELOG.md"

# «## 1.3.0 — 2026-08-26», дата необязательна
_HEAD = re.compile(
    r"^##\s+v?(\d+(?:\.\d+)*)\s*(?:[—–-]{1,2}\s*(\d{4}-\d{2}-\d{2}))?\s*$")


def _base() -> str:
    """Папка с ресурсами: _MEIPASS в собранном exe, иначе корень проекта."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return meipass
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def path() -> str:
    return os.path.join(_base(), NAME)


def read() -> str:
    try:
        with open(path(), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def parse(text: str) -> "OrderedDict[str, Dict]":
    """{версия: {tag, published, notes}} в порядке появления в файле."""
    out: "OrderedDict[str, Dict]" = OrderedDict()
    cur = None
    body: list = []

    def flush():
        if cur is None:
            return
        out[cur["tag"]] = {"tag": cur["tag"], "published": cur["published"],
                           "notes": "\n".join(body).strip()}

    for line in text.splitlines():
        m = _HEAD.match(line.rstrip())
        if m:
            flush()
            body = []
            cur = {"tag": m.group(1), "published": m.group(2) or ""}
            continue
        if cur is not None:
            body.append(line)
    flush()
    return out


def entries() -> "OrderedDict[str, Dict]":
    return parse(read())


def notes_for(version: str) -> str:
    """Описание одной версии. Пусто, если её в журнале нет."""
    return entries().get(str(version).lstrip("vV"), {}).get("notes", "")
