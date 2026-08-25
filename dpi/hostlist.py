"""
Список хостов, к которым применяется обход.

Если список пуст — обход применяется ко всему TLS/HTTP-трафику (режим «всё
подряд»). Если задан — только к совпавшим доменам (и их поддоменам): так мы
не трогаем лишний трафик и не ломаем «чистые» сайты.

Каждому домену дополнительно приписана группа сервиса (Discord, YouTube, …),
чтобы движок знал, чей это трафик, и применил именно её стратегию.
"""

from __future__ import annotations

import os
from typing import Dict, Optional


class HostList:
    def __init__(self) -> None:
        # домен -> id группы ("" = группа неизвестна, работаем по умолчанию)
        self._hosts: Dict[str, str] = {}
        # домены, которые не трогаем никогда — они сильнее любого совпадения
        self._exclude: Dict[str, str] = {}

    def exclude_many(self, hosts) -> int:
        count = 0
        for h in hosts:
            h = (h or "").strip().lower()
            if h and not h.startswith("#"):
                self._exclude[h] = ""
                count += 1
        return count

    @property
    def excluded(self) -> int:
        return len(self._exclude)

    @property
    def empty(self) -> bool:
        return not self._hosts

    @property
    def size(self) -> int:
        return len(self._hosts)

    def add_many(self, hosts, group: str = "") -> int:
        count = 0
        for h in hosts:
            h = (h or "").strip().lower()
            if h and not h.startswith("#"):
                self._hosts.setdefault(h, group)
                count += 1
        return count

    def add_map(self, mapping: Dict[str, str]) -> int:
        count = 0
        for h, g in (mapping or {}).items():
            h = (h or "").strip().lower()
            if h and not h.startswith("#"):
                self._hosts[h] = g or ""
                count += 1
        return count

    def load(self, path: str) -> int:
        if not path or not os.path.isfile(path):
            return 0
        count = 0
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                self._hosts.setdefault(line, "")
                count += 1
        return count

    def resolve(self, host: str) -> Optional[str]:
        """Группа, которой принадлежит host, либо None, если он не в списке.

        Пустой список означает «весь трафик наш», поэтому возвращается "" —
        это не None, и вызывающий отличает «не наш хост» от «наш, но группа
        неизвестна». Суффиксы проверяются от самого длинного к самому
        короткому, поэтому более конкретный домен выигрывает.
        """
        if not host:
            return "" if self.empty else None
        host = host.lower().rstrip(".")
        # список исключений сильнее всего остального, включая режим «весь трафик»
        if self._lookup(self._exclude, host) is not None:
            return None
        if self.empty:
            return ""
        return self._lookup(self._hosts, host)

    @staticmethod
    def _lookup(table: Dict[str, str], host: str) -> Optional[str]:
        got = table.get(host)
        if got is not None:
            return got
        # поддомены: a.b.example.com -> b.example.com -> example.com
        parts = host.split(".")
        for i in range(1, len(parts) - 1):
            got = table.get(".".join(parts[i:]))
            if got is not None:
                return got
        return None

    def match(self, host: str) -> bool:
        """Совпадает ли host со списком (прежний контракт, для CLI и тестов)."""
        return self.resolve(host) is not None
