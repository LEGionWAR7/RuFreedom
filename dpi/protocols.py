"""
Разбор TLS ClientHello и HTTP-запросов.

Задача модуля — найти внутри полезной нагрузки TCP-пакета имя хоста
(SNI в TLS, заголовок Host в HTTP) и сообщить, где именно оно лежит.
Движок разрезает пакет так, чтобы это имя оказалось на стыке двух
сегментов — тогда DPI не может его собрать и блокировка не срабатывает.
"""

from __future__ import annotations

from typing import Optional, Tuple


# ---------------------------------------------------------------------------
# TLS
# ---------------------------------------------------------------------------

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000


def is_tls_client_hello(payload: bytes) -> bool:
    """Похоже ли начало payload на TLS ClientHello."""
    if len(payload) < 6:
        return False
    if payload[0] != TLS_HANDSHAKE:
        return False
    # payload[1:3] — версия записи (0x0301..0x0303), допускаем диапазон
    if payload[1] != 0x03:
        return False
    if payload[5] != TLS_CLIENT_HELLO:
        return False
    return True


def find_sni(payload: bytes) -> Optional[Tuple[int, int, str]]:
    """
    Найти SNI в TLS ClientHello.

    Возвращает (start, end, hostname): start/end — смещения байт имени хоста
    внутри payload, hostname — само имя. None, если SNI не найден.
    """
    if not is_tls_client_hello(payload):
        return None

    try:
        # Заголовок записи (5) + handshake-заголовок (4)
        pos = 5 + 4
        pos += 2  # client version
        pos += 32  # random

        # session id
        sid_len = payload[pos]
        pos += 1 + sid_len

        # cipher suites
        cs_len = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2 + cs_len

        # compression methods
        cm_len = payload[pos]
        pos += 1 + cm_len

        # extensions
        if pos + 2 > len(payload):
            return None
        ext_total = int.from_bytes(payload[pos:pos + 2], "big")
        pos += 2
        ext_end = min(pos + ext_total, len(payload))

        while pos + 4 <= ext_end:
            ext_type = int.from_bytes(payload[pos:pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2:pos + 4], "big")
            ext_body = pos + 4
            if ext_type == EXT_SERVER_NAME:
                # server_name_list_len(2) + name_type(1) + name_len(2) + name
                p = ext_body + 2
                name_type = payload[p]
                name_len = int.from_bytes(payload[p + 1:p + 3], "big")
                name_start = p + 3
                name_end = name_start + name_len
                if name_type == 0 and name_end <= len(payload):
                    # SNI передаётся как ASCII A-label (punycode для IDN)
                    host = payload[name_start:name_end].decode("ascii", "ignore")
                    return name_start, name_end, host
            pos = ext_body + ext_len
    except (IndexError, ValueError):
        return None
    return None


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
                b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE ")


def is_http_request(payload: bytes) -> bool:
    return payload.startswith(HTTP_METHODS)


def find_http_host(payload: bytes) -> Optional[Tuple[int, int, str]]:
    """Найти значение заголовка Host. Возвращает (start, end, host) или None."""
    if not is_http_request(payload):
        return None
    lower = payload.lower()
    idx = lower.find(b"\r\nhost:")
    if idx == -1:
        return None
    value_start = idx + len(b"\r\nhost:")
    # пропустить пробелы
    while value_start < len(payload) and payload[value_start:value_start + 1] == b" ":
        value_start += 1
    value_end = payload.find(b"\r\n", value_start)
    if value_end == -1:
        return None
    host = payload[value_start:value_end].split(b":")[0].decode("ascii", "ignore")
    return value_start, value_end, host


# ---------------------------------------------------------------------------
# QUIC (HTTP/3 поверх UDP)
# ---------------------------------------------------------------------------
#
# QUIC ходит по UDP/443. DPI читает имя сайта из QUIC Initial-пакета (SNI лежит
# в TLS ClientHello внутри Initial, который шифруется общеизвестным ключом).
# Самый надёжный обход — «погасить» QUIC Initial, тогда браузер/приложение
# откатывается на обычный TLS поверх TCP, где работает наша TCP-десинхронизация.

def is_quic_long_header(payload: bytes) -> bool:
    """Long-header QUIC-пакет (старший бит первого байта = 1)."""
    if len(payload) < 5:
        return False
    return (payload[0] & 0x80) != 0


def is_quic_initial(payload: bytes) -> bool:
    """QUIC Initial-пакет (в нём передаётся SNI). Для него и нужен обход."""
    if not is_quic_long_header(payload):
        return False
    version = int.from_bytes(payload[1:5], "big")
    if version == 0:
        return False  # Version Negotiation — не Initial
    # тип пакета: биты 0x30 первого байта; для QUIC v1 0 == Initial
    return ((payload[0] & 0x30) >> 4) == 0
