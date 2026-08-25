"""
Фальшивые полезные нагрузки для десинхронизации DPI.

Зачем: техника «fake» работает так — перед настоящим ClientHello в то же
TCP-соединение отправляется ПОДДЕЛЬНЫЙ пакет с другим именем сайта. DPI
запоминает имя из подделки и пропускает соединение, а до сервера подделка
не доходит (её убивает низкий TTL / битая сумма / устаревший номер).

Ключевое требование: подделка обязана быть РАЗБИРАЕМЫМ ClientHello.
Раньше движок брал настоящий ClientHello и затирал первые 10 байт строкой
"www.w3.org" — при этом уничтожался заголовок TLS-записи (16 03 01 LL LL),
и DPI видел мусор, а не имя сайта. То есть все fake-стратегии не работали.

Здесь ClientHello собирается с нуля, побайтово, и содержит нужное имя в SNI.
"""

from __future__ import annotations

import os
import struct
from typing import Dict, Tuple

# Домены-приманки: обычные, заведомо не заблокированные сайты.
DEFAULT_FAKE_SNI = "www.google.com"

# Смещения внутри ClientHello. Они постоянные, потому что до session_id идут
# поля фиксированной длины: запись TLS (5) + заголовок рукопожатия (4) +
# версия (2) + random (32) = 43.
SID_LEN_OFF = 43
SID_OFF = 44
SID_SIZE = 32          # длина session_id у всех браузеров


def real_session_id(payload: bytes) -> bytes:
    """Вытащить session_id из НАСТОЯЩЕГО ClientHello.

    Нужен для приёма dupsid: подделка кладёт себе тот же session_id, что и
    настоящий пакет. DPI, который следит за session_id, считает их одним и
    тем же рукопожатием — и запоминает имя сайта из подделки. С разными
    session_id он видит два независимых рукопожатия и не обманывается.

    Пусто, если разобрать не вышло: тогда просто останется случайный.
    """
    if len(payload) < SID_OFF + SID_SIZE:
        return b""
    if payload[0] != 0x16 or payload[5] != 0x01:      # запись TLS + ClientHello
        return b""
    if payload[SID_LEN_OFF] != SID_SIZE:
        return b""                                    # нестандартная длина — не лезем
    return payload[SID_OFF:SID_OFF + SID_SIZE]


def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def _ext_server_name(host: str) -> bytes:
    name = host.encode("idna") if any(ord(c) > 127 for c in host) else host.encode("ascii")
    entry = b"\x00" + struct.pack("!H", len(name)) + name      # name_type=0 + имя
    return _ext(0x0000, struct.pack("!H", len(entry)) + entry)


# Расширения, которые есть в любом настоящем ClientHello. Без них некоторые
# DPI считают пакет «не похожим на браузер» и подделку не засчитывают.
_EXT_SUPPORTED_VERSIONS = _ext(0x002B, b"\x04\x03\x04\x03\x03")            # TLS1.3, TLS1.2
_EXT_SUPPORTED_GROUPS = _ext(0x000A, b"\x00\x08\x00\x1d\x00\x17\x00\x18\x00\x19")
_EXT_EC_POINT_FORMATS = _ext(0x000B, b"\x01\x00")
_SIG_ALGS = bytes.fromhex(
    "0403" "0503" "0603"        # ecdsa_secp256/384/521_sha256/384/512
    "0807" "0808" "0809" "080a" "080b"
    "0804" "0805" "0806"        # rsa_pss_rsae_sha256/384/512
    "0401" "0501" "0601"        # rsa_pkcs1_sha256/384/512
    "0303" "0301" "0302" "0402" "0502" "0602"
)
_EXT_SIG_ALGS = _ext(0x000D, struct.pack("!H", len(_SIG_ALGS)) + _SIG_ALGS)
_EXT_ALPN = _ext(0x0010, b"\x00\x0c\x02h2\x08http/1.1")
_EXT_SESSION_TICKET = _ext(0x0023, b"")
_EXT_RENEGOTIATION = _ext(0xFF01, b"\x00")

_CIPHERS = bytes.fromhex(
    "1301"  # TLS_AES_128_GCM_SHA256
    "1302"  # TLS_AES_256_GCM_SHA384
    "1303"  # TLS_CHACHA20_POLY1305_SHA256
    "c02b" "c02f" "c02c" "c030"
    "cca9" "cca8" "c013" "c014"
    "009c" "009d" "002f" "0035"
)


def build_client_hello(host: str = DEFAULT_FAKE_SNI, size: int = 0,
                       seed: bytes = b"") -> bytes:
    """Собрать корректный TLS 1.2/1.3 ClientHello с указанным SNI.

    `size` — желаемая длина payload; добор до неё делается стандартным
    расширением padding (0x0015), чтобы длина не выдавала подделку.
    """
    rnd = seed if len(seed) >= 64 else os.urandom(64)
    body = bytearray()
    body += b"\x03\x03"                                   # client_version = TLS 1.2
    body += rnd[:32]                                      # random
    body += bytes([32]) + rnd[32:64]                      # legacy_session_id
    body += struct.pack("!H", len(_CIPHERS)) + _CIPHERS   # cipher_suites
    body += b"\x01\x00"                                   # compression: null

    exts = (_ext_server_name(host) + _EXT_EC_POINT_FORMATS + _EXT_SUPPORTED_GROUPS
            + _EXT_SESSION_TICKET + _EXT_SIG_ALGS + _EXT_ALPN
            + _EXT_SUPPORTED_VERSIONS + _EXT_RENEGOTIATION)

    # добор длины через padding-расширение (4 байта заголовка + тело)
    if size:
        fixed = 5 + 4 + len(body) + 2 + len(exts)
        need = size - fixed
        if need >= 4:
            exts += _ext(0x0015, b"\x00" * (need - 4))

    body += struct.pack("!H", len(exts)) + exts

    hs = b"\x01" + len(body).to_bytes(3, "big") + bytes(body)   # ClientHello
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs    # TLS record


# Готовые подделки кэшируем: собирать их на каждый пакет незачем, а вот
# случайный random в каждой — наоборот, полезен (иначе DPI увидит копии).
_cache: Dict[Tuple[str, int], bytes] = {}


def tls_fake(host: str = DEFAULT_FAKE_SNI, size: int = 0,
             sid: bytes = b"") -> bytes:
    """Подделка ClientHello. `sid` — session_id настоящего пакета (приём dupsid)."""
    key = (host, size)
    got = _cache.get(key)
    if got is None:
        got = build_client_hello(host, size)
        _cache[key] = got
    # обновляем random, оставляя всю структуру — подделки не будут байт-в-байт
    out = bytearray(got)
    out[11:43] = os.urandom(32)
    if len(sid) == SID_SIZE:
        out[SID_OFF:SID_OFF + SID_SIZE] = sid
    else:
        # без dupsid session_id тоже должен быть случайным: иначе все подделки
        # с одним и тем же id заметны как штампованные
        out[SID_OFF:SID_OFF + SID_SIZE] = os.urandom(SID_SIZE)
    return bytes(out)


def http_fake(host: str = DEFAULT_FAKE_SNI) -> bytes:
    """Подделка для открытого HTTP: обычный GET на нейтральный домен."""
    return (f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n"
            f"Connection: keep-alive\r\n\r\n").encode("ascii")


def quic_fake(size: int = 1200) -> bytes:
    """Синтаксически корректный QUIC v1 Initial со случайным содержимым.

    Настоящий SNI туда не вписать: он лежит в зашифрованном CRYPTO-кадре, а
    ключ выводится из Destination Connection ID (нужен AES-GCM, которого нет
    в стандартной библиотеке). Поэтому подделка играет другую роль — она
    «занимает» соединение первой, и DPI не может достать имя сайта из неё.
    Основной режим для QUIC всё равно `drop`: он надёжнее и роняет соединение
    на TCP, где обход работает с полным знанием имени.
    """
    dcid = os.urandom(8)
    scid = os.urandom(8)
    head = bytearray()
    head += bytes([0xC0 | 0x03])                 # long header, Initial, pn_len=4
    head += (1).to_bytes(4, "big")               # version QUIC v1
    head += bytes([len(dcid)]) + dcid
    head += bytes([len(scid)]) + scid
    head += bytes(1)                             # token length = 0
    # поле Length само переменной длины — подбираем так, чтобы итоговый
    # размер пакета вышел ровно запрошенным
    for vlen in (1, 2, 4, 8):
        body_len = size - len(head) - vlen - 4
        if body_len < 64:
            continue
        v = _varint(body_len + 4)
        if len(v) == vlen:
            break
    else:
        body_len, v = 64, _varint(68)
    return bytes(head) + v + os.urandom(4) + os.urandom(body_len)


def _varint(value: int) -> bytes:
    """QUIC-переменная длина (RFC 9000, 16.)."""
    if value < 1 << 6:
        return bytes([value])
    if value < 1 << 14:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 1 << 30:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")
