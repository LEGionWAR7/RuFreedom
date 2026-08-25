"""
Диагностика: чем именно закрыт сервис.

Три болезни выглядят для пользователя одинаково («не работает»), но лечатся
по-разному, и путать их — значит два часа перебирать стратегии там, где ни одна
не может помочь:

  * `sni` — TCP открывается, рукопожатие с именем сайта рвётся, а БЕЗ имени
            проходит. Это DPI по имени сайта — его и обходит десинхронизация.
  * `ip`  — не открывается сам TCP. Блокировка по адресу: обманывать нечем,
            соединения просто нет. Десинк бессилен, нужен прокси или VPN.
  * `dns` — имя не разрешается или отдаёт мусор.

Проверка идёт ПРЯМЫМ соединением: обычный сокет системный прокси не использует,
поэтому мы видим настоящее состояние канала, а не то, что показывает браузер
через прокси.
"""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

from . import services

TIMEOUT = 5.0

# понятные подписи для интерфейса
VERDICT_TEXT = {
    "ok": "открывается",
    "sni": "DPI по имени сайта",
    "ip": "блокировка по IP",
    "ip-relay": "закрыт по IP, но есть точка входа",
    "dns": "не разрешается имя",
    "unknown": "рвётся, причина неясна",
}

# насколько всё плохо: берём худшее по хостам группы
_RANK = {"ok": 0, "unknown": 1, "sni": 2, "ip-relay": 3, "dns": 4, "ip": 5}

# Адреса Telegram, которые у многих провайдеров остаются открытыми, когда
# основные дата-центры закрыты наглухо. Через них поднимается WebSocket до
# DC2/DC4 (имя сайта — kwsN.web.telegram.org), и Telegram оживает без VPN.
# Проверено: рукопожатие проходит и отвечает «101 Switching Protocols».
TELEGRAM_RELAYS = ["149.154.167.220"]


def _tcp(ip: str, port: int = 443, timeout: float = TIMEOUT):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return s
    except Exception:
        s.close()
        return None


def _tls(sock, sni) -> bool:
    """Довести рукопожатие. sni=None — намеренно без имени сайта."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(sock, server_hostname=sni):
            return True
    except Exception:
        return False


# сколько адресов хоста пробовать, прежде чем объявить блокировку по IP
_MAX_IPS = 4


def classify_host(host: str, timeout: float = TIMEOUT) -> str:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except Exception:
        return "dns"
    ips: List[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in ips:
            ips.append(addr)
    if not ips:
        return "dns"

    # Крупные сервисы отвечают с десятка адресов, и один-два из них могут быть
    # недоступны сами по себе. Раньше проверялся только первый — и если не
    # везло, живой сервис объявлялся заблокированным по IP, после чего обход
    # его переставал трогать. Поэтому пробуем несколько.
    s = None
    for ip in ips[:_MAX_IPS]:
        s = _tcp(ip, 443, timeout)
        if s is not None:
            break
    if s is None:
        return "ip"

    if _tls(s, host):
        return "ok"

    # с именем не вышло — пробуем без него. Если так проходит, значит режут
    # именно по имени сайта, а канал до сервера живой.
    for ip in ips[:_MAX_IPS]:
        s2 = _tcp(ip, 443, timeout)
        if s2 is not None:
            return "sni" if _tls(s2, None) else "unknown"
    return "unknown"


def telegram_relay_alive(timeout: float = TIMEOUT) -> bool:
    """Есть ли открытая точка входа в Telegram, минуя закрытые дата-центры.

    Основные адреса Telegram закрывают по IP, но отдельные relay-адреса часто
    остаются доступны. Через такой адрес WebSocket-мост (tg-ws-proxy и ему
    подобные) поднимает связь с дата-центром. Проверяем не просто TCP, а полное
    TLS-рукопожатие с именем kws2.web.telegram.org — иначе можно принять за
    победу чужой сервер на том же адресе.
    """
    for ip in TELEGRAM_RELAYS:
        s = _tcp(ip, 443, timeout)
        if s is None:
            continue
        if _tls(s, "kws2.web.telegram.org"):
            return True
    return False


def _tell(progress, done: int, total: int) -> None:
    """Отчёт о ходе не имеет права уронить проверку."""
    try:
        progress(done, total)
    except Exception:
        pass


def classify_groups(group_ids, timeout: float = TIMEOUT,
                    progress=None) -> Dict[str, str]:
    """{группа: худший вердикт по её проверочным хостам}.

    `progress(готово, всего)` — необязательный отчёт о ходе: вызывается по мере
    того, как приходят ответы. Нужен экрану загрузки, чтобы полоса показывала
    настоящую работу, а не бегала вхолостую.
    """
    pairs: List = []
    for gid in group_ids:
        for host in services.probe_hosts(gid):
            pairs.append((gid, host))
    if not pairs:
        return {}
    out: Dict[str, str] = {}
    done = 0
    if progress:
        _tell(progress, 0, len(pairs))
    with ThreadPoolExecutor(max_workers=max(1, min(16, len(pairs)))) as ex:
        futs = [(gid, ex.submit(classify_host, host, timeout)) for gid, host in pairs]
        for gid, fut in futs:
            try:
                v = fut.result()
            except Exception:
                v = "unknown"
            if _RANK.get(v, 1) > _RANK.get(out.get(gid, "ok"), 0):
                out[gid] = v
            out.setdefault(gid, v)
            done += 1
            if progress:
                _tell(progress, done, len(pairs))

    # Telegram закрыт по IP — но это ещё не приговор: если открыта точка входа,
    # его поднимает WebSocket-мост, и говорить «безнадёжно» было бы неправдой
    if out.get("telegram") == "ip" and telegram_relay_alive(timeout):
        out["telegram"] = "ip-relay"
    return out


def hopeless(verdict: str) -> bool:
    """Случаи, где перебирать стратегии обхода DPI бессмысленно.

    Соединения нет вовсе — переписывать нечего. Сюда же попадает `ip-relay`:
    сам обход DPI и там не поможет, но выход есть, и интерфейс о нём скажет.
    """
    return verdict in ("ip", "ip-relay", "dns")


def system_proxy() -> str:
    """Адрес системного прокси, если он включён (иначе пустая строка).

    Важно знать: когда прокси включён, большинство приложений ходит через него,
    а не напрямую — и обход DPI им попросту не нужен и не применяется.
    """
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                             r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        try:
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if not enabled:
                return ""
            server, _ = winreg.QueryValueEx(key, "ProxyServer")
            return str(server or "")
        finally:
            winreg.CloseKey(key)
    except Exception:
        return ""
