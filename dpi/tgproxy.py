"""
Telegram: поиск локального прокси и настройка клиента.

Telegram у многих провайдеров закрыт НЕ по имени сайта, а по IP: соединение до
дата-центров не устанавливается вовсе. Обход DPI там бессилен — переписывать
нечего. Единственный рабочий путь — прокси, и он у пользователя обычно уже
запущен: NekoBox, v2rayN, Hiddify, Clash, tg-ws-proxy.

Модуль ищет их широко и проверяет по-настоящему: не «порт открыт», а «через
этот порт удалось соединиться с дата-центром Telegram». Порт может слушать
что угодно — веб-сервер, отладчик, игра, — поэтому верим только проверке.
"""

from __future__ import annotations

import json
import os
import socket
import struct
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

# Порты, на которых обычно висят локальные клиенты. Диапазонами, а не
# перечислением: у одного и того же клиента порт легко отличается на единицу.
def _port_pool() -> List[int]:
    ports: List[int] = []
    ports += list(range(2080, 2091))      # NekoBox / Nekoray
    ports += list(range(10800, 10820))    # v2rayN, sing-box
    ports += list(range(1080, 1091))      # классический SOCKS
    ports += list(range(7890, 7900))      # Clash / Mihomo
    ports += list(range(20170, 20180))    # sing-box по умолчанию
    ports += [9050, 9150]                 # Tor
    ports += [1443]                       # tg-ws-proxy (MTProto)
    ports += [8080, 8081, 8118, 3128]     # HTTP-прокси
    ports += [4444, 8388, 10086]          # разное
    seen, out = set(), []
    for p in ports:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


COMMON_PORTS: List[int] = _port_pool()

# Адрес дата-центра Telegram: по нему и проверяем, что прокси реально уводит
# трафик наружу, а не просто отвечает на рукопожатие.
TG_DC = ("149.154.167.51", 443)

SOCKS5_ERRORS = {
    1: "общий сбой", 2: "запрещено правилами", 3: "сеть недоступна",
    4: "хост недоступен", 5: "соединение отклонено", 6: "истекло время",
    7: "команда не поддерживается", 8: "тип адреса не поддерживается",
}

# процессы, по которым понятно: клиент запущен, но порт мы не угадали
KNOWN_CLIENTS = {
    "nekobox": "NekoBox", "nekoray": "Nekoray", "v2ray": "v2rayN",
    "xray": "Xray", "sing-box": "sing-box", "clash": "Clash",
    "mihomo": "Mihomo", "hiddify": "Hiddify", "throne": "Throne",
    "amnezia": "AmneziaVPN", "outline": "Outline", "shadowsocks": "Shadowsocks",
    "tgwsproxy": "tg-ws-proxy", "tg-ws-proxy": "tg-ws-proxy",
}


def _listening(port: int, host: str = "127.0.0.1", timeout: float = 0.35) -> bool:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except Exception:
        return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe_socks5(port: int, host: str = "127.0.0.1",
                 target: Tuple[str, int] = TG_DC, timeout: float = 4.0):
    """SOCKS5 на порту? Возвращает (доходит ли до Telegram, пояснение)."""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except Exception:
        s.close()
        return False, "никто не слушает"
    try:
        s.sendall(b"\x05\x01\x00")                    # SOCKS5, без авторизации
        head = s.recv(2)
        if len(head) < 2 or head[0] != 0x05:
            return False, "это не SOCKS5"
        if head[1] != 0x00:
            return False, "прокси требует логин и пароль"
        addr = target[0].encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr
                  + struct.pack("!H", target[1]))
        rep = s.recv(10)
        if len(rep) < 2:
            return False, "прокси не ответил"
        if rep[1] != 0x00:
            return False, "до Telegram не доходит: " + SOCKS5_ERRORS.get(rep[1], "код %d" % rep[1])
        return True, "доходит до Telegram"
    except Exception as exc:
        return False, type(exc).__name__
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe_http(port: int, host: str = "127.0.0.1",
               target: Tuple[str, int] = TG_DC, timeout: float = 4.0):
    """HTTP-прокси с методом CONNECT — второй распространённый вид."""
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((host, port))
    except Exception:
        s.close()
        return False, "никто не слушает"
    try:
        s.sendall(f"CONNECT {target[0]}:{target[1]} HTTP/1.1\r\n"
                  f"Host: {target[0]}:{target[1]}\r\n\r\n".encode())
        head = s.recv(64)
        if not head.startswith(b"HTTP/"):
            return False, "это не HTTP-прокси"
        code = head.split(b" ")[1:2]
        if code and code[0] == b"200":
            return True, "доходит до Telegram"
        return False, "прокси отказал: " + head.split(b"\r\n")[0].decode("latin1", "ignore")
    except Exception as exc:
        return False, type(exc).__name__
    finally:
        try:
            s.close()
        except Exception:
            pass


def find_ws_bridge(host: str = "127.0.0.1") -> Optional[dict]:
    """Найти запущенный WebSocket-мост (tg-ws-proxy и подобные).

    Это не SOCKS5, а MTProto-прокси: снаружи его секрет не выяснить, поэтому
    читаем конфиг, который он пишет себе сам. Без секрета ссылку не собрать.
    """
    candidates = []
    for base in (os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA")):
        if base:
            candidates.append(os.path.join(base, "tg-ws-proxy", "config.json"))
    candidates.append(os.path.join(os.path.expanduser("~"), "tg-ws-proxy",
                                   "config.json"))
    for path in candidates:
        try:
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8") as fh:
                cfg = json.load(fh)
        except (OSError, ValueError):
            continue
        port = int(cfg.get("port") or 1443)
        secret = str(cfg.get("secret") or "")
        if not secret or not _listening(port, host):
            continue
        return {"host": host, "port": port, "secret": secret, "kind": "mtproto",
                "note": "WebSocket-мост запущен", "title": "tg-ws-proxy"}
    return None


def running_clients() -> List[str]:
    """Какие прокси-клиенты запущены — чтобы объяснить, если порт не нашёлся."""
    try:
        from .anticheat import _process_names
        names = _process_names()
    except Exception:
        return []
    found = []
    for n in names:
        stem = n.rsplit(".", 1)[0]
        for key, title in KNOWN_CLIENTS.items():
            if key in stem and title not in found:
                found.append(title)
    return found


def system_proxy_endpoint() -> Optional[Tuple[str, int]]:
    """Адрес системного прокси — его тоже стоит проверить, он часто рабочий."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        try:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if not enabled:
                return None
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
        finally:
            winreg.CloseKey(key)
    except Exception:
        return None
    text = str(server or "")
    if "=" in text:                     # вид "http=1.2.3.4:8080;socks=..."
        for part in text.split(";"):
            if "socks" in part.lower() and "=" in part:
                text = part.split("=", 1)[1]
                break
        else:
            text = text.split(";")[0].split("=", 1)[-1]
    if ":" not in text:
        return None
    host, _, port = text.rpartition(":")
    try:
        return host or "127.0.0.1", int(port)
    except ValueError:
        return None


def scan(host: str = "127.0.0.1") -> Dict:
    """Полный поиск. Возвращает найденное, проверенное и объяснение.

    {"best": {...} | None, "all": [...], "clients": [...], "scanned": N}
    """
    bridge = find_ws_bridge(host)
    found: List[dict] = []
    if bridge:
        found.append(bridge)

    ports = list(COMMON_PORTS)
    sysp = system_proxy_endpoint()
    if sysp and sysp[0] in ("127.0.0.1", "localhost") and sysp[1] not in ports:
        ports.append(sysp[1])

    # сперва быстро отсеиваем закрытые порты — так проверка идёт секунды, а не
    # минуты: полноценное рукопожатие к каждому из полусотни портов слишком долго
    with ThreadPoolExecutor(max_workers=64) as ex:
        alive = [p for p, ok in zip(ports, ex.map(lambda p: _listening(p, host), ports)) if ok]

    for port in alive:
        if bridge and port == bridge["port"]:
            continue
        ok, why = probe_socks5(port, host)
        if ok:
            found.append({"host": host, "port": port, "kind": "socks5",
                          "note": why, "title": f"SOCKS5 {host}:{port}"})
            continue
        ok2, why2 = probe_http(port, host)
        if ok2:
            found.append({"host": host, "port": port, "kind": "http",
                          "note": why2, "title": f"HTTP-прокси {host}:{port}"})
            continue
        # порт живой, но не прокси или не пускает — сохраним для объяснения
        found.append({"host": host, "port": port, "kind": "", "broken": True,
                      "note": why if "не слушает" not in why else why2,
                      "title": f"{host}:{port}"})

    working = [f for f in found if not f.get("broken")]
    # MTProto-мост предпочтительнее: он поднят именно ради Telegram
    working.sort(key=lambda f: 0 if f["kind"] == "mtproto" else 1)
    return {"best": working[0] if working else None,
            "all": found,
            "clients": running_clients(),
            "scanned": len(ports),
            "alive": len(alive)}


def find_local_socks(host: str = "127.0.0.1") -> Optional[dict]:
    """Совместимость со старым вызовом: только лучший найденный."""
    res = scan(host)
    if res["best"]:
        return res["best"]
    broken = [f for f in res["all"] if f.get("broken")]
    return broken[0] if broken else None


def tg_socks_link(host: str, port: int) -> str:
    """Ссылка, по которой Telegram сам предложит добавить прокси."""
    from urllib.parse import urlencode
    return "tg://socks?" + urlencode({"server": host, "port": int(port)})


def tg_mtproto_link(host: str, port: int, secret: str) -> str:
    from urllib.parse import urlencode
    return "tg://proxy?" + urlencode({"server": host, "port": int(port),
                                      "secret": secret})


def link_for(found: dict) -> str:
    if found.get("kind") == "mtproto":
        return tg_mtproto_link(found["host"], found["port"], found.get("secret", ""))
    return tg_socks_link(found["host"], found["port"])
