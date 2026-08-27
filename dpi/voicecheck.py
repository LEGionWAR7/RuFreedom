"""
Готов ли Discord к голосу и демонстрации экрана.

Обычная диагностика проверяет `discord.com` и `gateway.discord.gg`. В России
оба открываются, и группа получает вердикт «не заблокирован» — после чего
Discord целиком выпадает из обхода. А голос при этом не работает: он живёт
на СВОЁМ домене (`*.discord.media`), который диагностика не трогала вовсе.
Из-за этого «подобрал с первого раза» для Discord не срабатывало никогда:
подбирать было нечего, группа считалась здоровой.

Здесь проверяется то, от чего голос и демонстрация экрана зависят на самом
деле:

  * `latency.discord.media` — узел голосовой инфраструктуры. Имя постоянное
    (в отличие от `finland14084.discord.media`, который выдаётся под сессию),
    поэтому его можно проверять заранее.
  * `gateway.discord.gg` — через него приходит адрес голосового сервера.
    Без гейтвея до голоса дело не доходит вовсе.
  * `cdn.discordapp.com` — картинки, вложения, аватарки. Именно он отвечает
    за «Discord не прогружается».
  * локальный RPC — признак того, что клиент запущен и жив. Игры и оверлеи
    общаются с ним через 127.0.0.1:6463..6472.

Проверить сам голосовой канал снаружи нельзя: адрес голосового сервера
выдаётся под сессию, после входа в канал. Поэтому здесь — готовность
инфраструктуры, а не «звук точно пойдёт», и говорить надо ровно это.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional

from . import autotune

# Постоянные имена, по которым видно состояние голоса и загрузки контента.
VOICE_HOST = "latency.discord.media"
GATEWAY_HOST = "gateway.discord.gg"
CDN_HOST = "cdn.discordapp.com"

# Локальный RPC клиента Discord. Порты официальные и не меняются.
RPC_PORTS = range(6463, 6473)

# Имена процессов клиента: обычный, PTB, Canary, Development.
CLIENT_NAMES = ("discord", "discordptb", "discordcanary", "discorddevelopment")


def rpc_port(timeout: float = 0.25) -> int:
    """Порт локального RPC, если клиент запущен. 0 — не найден."""
    for port in RPC_PORTS:
        s = socket.socket()
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", port))
            return port
        except Exception:                             # noqa: BLE001
            continue
        finally:
            try:
                s.close()
            except Exception:                         # noqa: BLE001
                pass
    return 0


def client_running() -> bool:
    """Запущен ли клиент Discord."""
    try:
        from .conflicts import process_names
        names = process_names()
    except Exception:                                 # noqa: BLE001
        return False
    for name in names:
        stem = name.rsplit(".", 1)[0]
        if stem in CLIENT_NAMES:
            return True
    return False


def report(timeout: float = 4.0) -> Dict:
    """Что сейчас с Discord. Все проверки идут разом.

    Возвращает поля, а не готовый приговор: решение принимает вызывающий.
    `text` — одна строка для человека, уже с объяснением, что делать.
    """
    checks = {"voice": VOICE_HOST, "gateway": GATEWAY_HOST, "cdn": CDN_HOST}
    out: Dict = {}
    with ThreadPoolExecutor(max_workers=len(checks) + 1) as ex:
        futs = {key: ex.submit(autotune.test_host, host, timeout)
                for key, host in checks.items()}
        port_fut = ex.submit(rpc_port)
        for key, fut in futs.items():
            try:
                out[key] = bool(fut.result())
            except Exception:                         # noqa: BLE001
                out[key] = False
        try:
            out["rpc"] = int(port_fut.result())
        except Exception:                             # noqa: BLE001
            out["rpc"] = 0

    out["client"] = client_running()
    out["ok"] = bool(out["voice"] and out["gateway"])
    out["text"] = summary(out)
    return out


def summary(state: Dict) -> str:
    """Одна строка: что именно не так и что это значит."""
    broken: List[str] = []
    if not state.get("gateway"):
        broken.append("шлюз")
    if not state.get("voice"):
        broken.append("голосовые серверы")
    if not state.get("cdn"):
        broken.append("картинки и вложения")

    if broken:
        return ("Не открывается: " + ", ".join(broken)
                + ". Обход для Discord нужен — без него голос и демонстрация "
                  "экрана не заработают.")
    if not state.get("client"):
        return ("Всё открывается. Клиент Discord не запущен — проверить голос "
                "по-настоящему можно только с ним.")
    if not state.get("rpc"):
        return ("Всё открывается, клиент запущен, но локальный RPC не отвечает. "
                "Обычно помогает перезапуск Discord.")
    return "Всё открывается, клиент запущен, RPC отвечает — голос должен работать."


def blocked_hosts(state: Optional[Dict] = None) -> List[str]:
    """Какие из постоянных имён закрыты. Пусто — значит всё открыто."""
    st = state if state is not None else report()
    out = []
    if not st.get("gateway"):
        out.append(GATEWAY_HOST)
    if not st.get("voice"):
        out.append(VOICE_HOST)
    if not st.get("cdn"):
        out.append(CDN_HOST)
    return out
