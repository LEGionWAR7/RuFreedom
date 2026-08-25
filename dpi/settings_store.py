"""
Сохранение/загрузка пользовательского профиля настроек GUI.

Профиль лежит рядом с программой в config/settings.json и хранит выбранную
стратегию, режим QUIC и набор включённых категорий сервисов.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict

_DEFAULTS: Dict[str, Any] = {
    # Профиль по умолчанию — им работают группы, которым свой не подобран.
    # Выбран не наугад: разрез на 1-м байте с перекрытием 568 байт подставным
    # ClientHello — это то, что реально пробивает Discord и YouTube там, где
    # обычное разрезание не даёт ничего (DPI собирает TCP-поток обратно).
    "strategy": "multisplit",
    "quic_mode": "drop",
    "fooling": "none",
    "split_mode": "pos1",
    "fake_ttl": 4,
    "fake_count": 2,
    "seg_count": 2,
    "seqovl": 568,
    "all_traffic": False,
    "groups": {},              # {"discord": True, ...}
    "profiles": {},            # {"discord": {...}, ...} — свой обход на группу
    "voice_fake": True,        # обход для голосовых каналов Discord (UDP)
    "categories": {},          # старый ключ, пишем ещё релиз ради отката
    "start_minimized": False,
    "click_sound": "Нажатие кнопки",
    # авто-подстройка под сеть этого пользователя
    "auto_config": True,       # подбирать обход автоматически
    "auto_tuned": False,       # уже подбирали на этой машине
    "watchdog": True,          # перепобирать обход, когда сервис отвалился
    # Крайняя мера: гасить обход целиком на время игры. По умолчанию
    # ВЫКЛЮЧЕНО — вместе с обходом отвалится и Discord. Сначала работает
    # список ANTICHEAT_DOMAINS: он обходит античиты стороной, не трогая
    # остальное. Включать это стоит, только если игра не стартует даже так.
    "pause_on_anticheat": False,
}


# Файл настроек назывался ruszapret-settings.json до переименования
# программы в RuFreedom. Старое имя читаем, если нового ещё нет: иначе у
# всех, кто уже пользовался программой, настройки просто исчезли бы.
_LEGACY_NAME = "ruszapret-settings.json"
_NAME = "rufreedom-settings.json"


def _path() -> str:
    # В собранном .exe пишем профиль рядом с программой (временная папка
    # onefile-сборки стирается между запусками).
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(sys.executable), _NAME)
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "config", "settings.json")


def _legacy_path() -> str:
    if getattr(sys, "frozen", False):
        return os.path.join(os.path.dirname(sys.executable), _LEGACY_NAME)
    return ""


def load() -> Dict[str, Any]:
    data = dict(_DEFAULTS)
    path = _path()
    if not os.path.isfile(path):
        old = _legacy_path()
        if old and os.path.isfile(old):
            path = old            # первый запуск после переименования
    if os.path.isfile(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data.update(json.load(fh))
        except (OSError, ValueError):
            pass
    return data


def save(data: Dict[str, Any]) -> None:
    path = _path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
    except OSError:
        pass
