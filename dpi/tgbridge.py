"""
Встроенный мост для Telegram: свой SOCKS5, который прячет MTProto в WebSocket.

Зачем. Telegram у многих провайдеров закрыт по IP: до дата-центров не доходит
даже TCP, и обход DPI бессилен — переписывать нечего. Но у Telegram есть вторая
дверь: те же дата-центры принимают MTProto внутри обычного WebSocket по адресу
`wss://kwsN.web.telegram.org/apiws` — так работает веб-версия. Если хоть один
адрес Telegram доступен, через него поднимается WebSocket, а внутри идёт тот же
самый поток, что Telegram Desktop послал бы напрямую.

Почему без шифрования. Настоящий MTProto-прокси обязан расшифровать первые 64
байта клиента, чтобы узнать номер дата-центра, — для этого нужен AES. Мы идём
проще: поднимаем SOCKS5, и номер дата-центра берём из адреса, к которому клиент
попросил подключиться. Поток при этом не трогаем вообще — он и так зашифрован
самим Telegram. Ни одной криптографической библиотеки не требуется.

Почему адреса ищутся, а не зашиты. Рабочие точки входа выключают: адрес,
который отвечал утром, к вечеру уже закрыт. Поэтому мост сканирует подсети
Telegram, находит живые и проверяет их настоящим WebSocket-рукопожатием.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import socket
import ssl
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, List, Optional, Tuple

# Подсети Telegram. Дата-центров пять, но адреса внутри подсетей переезжают,
# поэтому ищем по всему диапазону, а не по списку конкретных адресов.
# ГДЕ ИСКАТЬ точки входа для моста. Список узкий намеренно: каждый адрес
# здесь проверяется вживую, и лишняя тысяча адресов — это лишние минуты
# ожидания. Сюда входят подсети, где точки входа встречаются на практике.
TG_NETS: List[str] = [
    "149.154.160.0/22", "149.154.164.0/22", "149.154.167.0/24",
    "149.154.171.0/24", "149.154.175.0/24",
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22",
    "91.108.16.0/22", "91.108.56.0/22",
    "91.105.192.0/23", "95.161.64.0/22",
]

# ЧТО СЧИТАТЬ адресом Telegram. Здесь список полный, официальный, и это
# совсем другая задача: по нему мост решает, свой ли адрес просит клиент.
#
# Раньше на оба вопроса отвечал один список — и дырки в нём стоили дорого.
# 149.154.172.10 это обычный адрес Telegram, но в список он не попадал, и
# мост отвечал «запрещено правилами». Для Telegram такой ответ означает не
# «сеть недоступна», а «прокси настроен неверно»: он показывал окно и
# выключал прокси. Диапазон 149.154.160.0/20 закрывает всю область целиком.
#
# Смешивать эти списки нельзя ещё и потому, что широкий список превращает
# поиск точек входа в перебор десятков тысяч адресов.
TG_OWN_NETS: List[str] = [
    "149.154.160.0/20",
    "91.108.4.0/22", "91.108.8.0/22", "91.108.12.0/22",
    "91.108.16.0/22", "91.108.20.0/22", "91.108.56.0/22",
    "91.105.192.0/23", "95.161.64.0/20", "185.76.151.0/24",
]

# Рабочие адреса дата-центров. По подсети их различить НЕЛЬЗЯ: DC1 и DC3
# живут в одной 149.154.175.0/24, DC2 и DC4 — в одной 149.154.167.0/24.
# Раньше номер брался по подсети, и клиент, попросивший DC3, получал туннель
# в DC1: соединение поднималось, но поток MTProto оказывался чужим — связь
# устанавливалась и почти сразу рассыпалась.
DC_BY_IP = {
    "149.154.175.50": 1,
    "149.154.167.51": 2,
    "149.154.175.100": 3,
    "149.154.167.91": 4,
    "91.108.56.130": 5,
}

# Какой дата-центр живёт в какой подсети — запасной ответ, когда точного
# совпадения нет. По нему выбирается имя kwsN.
DC_BY_NET: List[Tuple[str, int]] = [
    ("149.154.175.0/24", 1), ("149.154.167.0/24", 2), ("149.154.171.0/24", 5),
    ("149.154.160.0/22", 2), ("149.154.164.0/22", 2),
    ("91.108.4.0/22", 5), ("91.108.8.0/22", 5), ("91.108.12.0/22", 5),
    ("91.108.16.0/22", 5), ("91.108.56.0/22", 5),
    ("91.105.192.0/23", 2), ("95.161.64.0/22", 2),
]

WS_PATH = "/apiws"
DEFAULT_PORT = 1081          # свой SOCKS5; 1080 часто занят чужим клиентом


def dc_for_ip(ip: str) -> int:
    """Номер дата-центра по адресу, к которому просится клиент."""
    exact = DC_BY_IP.get(ip)
    if exact:
        return exact
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return 2
    for net, dc in DC_BY_NET:
        if addr in ipaddress.ip_network(net):
            return dc
    return 2


def is_telegram_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n) for n in TG_OWN_NETS)


def ws_domain(dc: int) -> str:
    return f"kws{dc if dc in (1, 2, 3, 4, 5) else 2}.web.telegram.org"


# --- поиск точки входа -----------------------------------------------------
def _tcp_open(ip: str, timeout: float = 1.2) -> Optional[str]:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, 443))
        return ip
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def verify_entry(ip: str, dc: int = 2, timeout: float = 8.0) -> bool:
    """Поднимается ли через этот адрес WebSocket к дата-центру."""
    try:
        conn = WsConn.connect(ip, ws_domain(dc), timeout=timeout)
    except Exception:
        return False
    conn.close()
    return True


def find_entries(progress: Optional[Callable[[str, int, int], None]] = None,
                 stop: Optional[threading.Event] = None,
                 limit: int = 3,
                 on_found: Optional[Callable[[dict], None]] = None) -> List[dict]:
    """Просканировать подсети Telegram и вернуть проверенные точки входа.

    Сначала быстрый TCP-проход (адресов тысячи, рукопожатие с каждым было бы
    слишком долго), затем настоящая проверка WebSocket у откликнувшихся.

    Проверка идёт ПАРАЛЛЕЛЬНО. Раньше она шла по одному адресу за раз, а у
    каждого свой таймаут в восемь секунд — три точки входа набирались почти
    полминуты, и всё это время человек не видел ничего. Теперь первая же
    удача уходит в `on_found` сразу, не дожидаясь остальных.
    """
    found: List[dict] = []
    nets = list(TG_NETS)
    for i, net in enumerate(nets, 1):
        if stop is not None and stop.is_set():
            break
        addrs = [str(a) for a in ipaddress.ip_network(net).hosts()]
        if progress:
            progress(net, i, len(nets))
        with ThreadPoolExecutor(max_workers=160) as ex:
            alive = [x for x in ex.map(_tcp_open, addrs) if x]
        if not alive:
            continue

        def _check(ip):
            if stop is not None and stop.is_set():
                return None
            dc = dc_for_ip(ip)
            return {"ip": ip, "dc": dc, "net": net} if verify_entry(ip, dc) else None

        with ThreadPoolExecutor(max_workers=min(8, len(alive))) as ex:
            futs = [ex.submit(_check, ip) for ip in alive]
            for fut in futs:
                if stop is not None and stop.is_set():
                    break
                try:
                    item = fut.result()
                except Exception:            # noqa: BLE001
                    item = None
                if item is None:
                    continue
                found.append(item)
                if on_found:
                    try:
                        on_found(item)
                    except Exception:        # noqa: BLE001
                        pass
                if len(found) >= limit:
                    return found
    return found


# --- WebSocket поверх TLS --------------------------------------------------
class WsConn:
    """Минимальный клиент WebSocket: ровно столько, сколько нужно для MTProto.

    Кадры от клиента обязаны быть замаскированы (RFC 6455), от сервера — нет.
    Внутри ходят двоичные кадры, содержимое не трогаем.
    """

    def __init__(self, sock, tls):
        self._sock = sock
        self._tls = tls
        self._buf = b""

    @classmethod
    def connect(cls, ip: str, sni: str, path: str = WS_PATH,
                timeout: float = 8.0) -> "WsConn":
        raw = socket.create_connection((ip, 443), timeout=timeout)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        key = base64.b64encode(os.urandom(16)).decode()
        tls.sendall(
            f"GET {path} HTTP/1.1\r\nHost: {sni}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Protocol: binary\r\n"
            f"Origin: https://{sni}\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = tls.recv(512)
            if not chunk:
                raise ConnectionError("сервер закрыл соединение на рукопожатии")
            head += chunk
            if len(head) > 8192:
                raise ConnectionError("слишком длинный ответ на рукопожатие")
        line = head.split(b"\r\n", 1)[0].decode("latin1")
        if "101" not in line:
            raise ConnectionError(f"WebSocket не поднялся: {line}")
        # Таймаут был нужен только на подключение и рукопожатие. Дальше его
        # надо СНЯТЬ, иначе он остаётся на сокете навсегда.
        #
        # Это и была причина «прокси работает, а через пару секунд
        # выключается». Соединение MTProto почти всё время молчит: клиент
        # что-то скачал и ждёт. Через восемь секунд тишины recv на сокете
        # срывался по таймауту, перекачка считала это концом связи и закрывала
        # соединение клиента. Telegram видел, что прокси рвёт соединения одно
        # за другим, и объявлял его неверно настроенным.
        # Снимаем таймаут с TLS-обёртки, и только с неё: после wrap_socket
        # исходный сокет отсоединён, и обращение к нему на Windows падает
        # с «операция над не-сокетом».
        tls.settimeout(None)
        conn = cls(raw, tls)
        conn._buf = head.split(b"\r\n\r\n", 1)[1]
        return conn

    # -- отправка ---------------------------------------------------------
    def send_binary(self, data: bytes) -> None:
        mask = os.urandom(4)
        n = len(data)
        head = bytearray([0x82])                     # FIN + двоичный кадр
        if n < 126:
            head.append(0x80 | n)
        elif n < (1 << 16):
            head.append(0x80 | 126)
            head += struct.pack("!H", n)
        else:
            head.append(0x80 | 127)
            head += struct.pack("!Q", n)
        head += mask
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
        self._tls.sendall(bytes(head) + masked)

    # -- приём ------------------------------------------------------------
    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._tls.recv(65536)
            if not chunk:
                raise ConnectionError("соединение закрыто")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv_binary(self) -> Optional[bytes]:
        """Следующий двоичный кадр. None — соединение закрыто по-хорошему."""
        while True:
            head = self._read(2)
            opcode = head[0] & 0x0F
            masked = bool(head[1] & 0x80)
            length = head[1] & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._read(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._read(8))[0]
            mask = self._read(4) if masked else b""
            body = self._read(length) if length else b""
            if masked and body:
                body = bytes(b ^ mask[i & 3] for i, b in enumerate(body))
            if opcode == 0x8:                        # закрытие
                return None
            if opcode == 0x9:                        # ping -> pong
                self._send_control(0xA, body)
                continue
            if opcode in (0x1, 0x2, 0x0):
                return body
            # прочие кадры игнорируем

    def _send_control(self, opcode: int, data: bytes = b"") -> None:
        mask = os.urandom(4)
        payload = bytes(b ^ mask[i & 3] for i, b in enumerate(data))
        self._tls.sendall(bytes([0x80 | opcode, 0x80 | len(data)]) + mask + payload)

    def close(self) -> None:
        for sock in (self._tls, self._sock):
            try:
                sock.close()
            except Exception:
                pass


# --- SOCKS5, который уводит Telegram в WebSocket ---------------------------
class TgBridge:
    """Локальный SOCKS5. Соединения к Telegram уводит в WebSocket, остальные
    отклоняет — это мост для одного сервиса, а не общий прокси."""

    def __init__(self, entries: List[dict], port: int = DEFAULT_PORT,
                 host: str = "127.0.0.1",
                 logger: Optional[Callable[[str], None]] = None) -> None:
        self.entries = list(entries)
        self.port = int(port)
        self.host = host
        self._log = logger or (lambda *_: None)
        self._srv: Optional[socket.socket] = None
        self._running = False
        self.stats = {"sessions": 0, "active": 0, "bytes_up": 0, "bytes_down": 0}

    @property
    def running(self) -> bool:
        return self._running

    # сколько ждать точку входа, прежде чем признать её мёртвой
    ENTRY_TIMEOUT = 5.0

    def entries_for(self, dc: int) -> List[dict]:
        """Точки входа в порядке предпочтения: сначала свой дата-центр.

        Порядок важен: точки выключают, и висеть на первой попавшейся нельзя —
        клиент в это время просто ждёт, ничего не понимая.
        """
        mine = [e for e in self.entries if e.get("dc") == dc and not e.get("dead")]
        rest = [e for e in self.entries if e.get("dc") != dc and not e.get("dead")]
        dead = [e for e in self.entries if e.get("dead")]
        return mine + rest + dead

    def _open_ws(self, dc: int):
        """Поднять WebSocket через первую живую точку. None — живых нет."""
        for entry in self.entries_for(dc):
            try:
                ws = WsConn.connect(entry["ip"], ws_domain(dc),
                                    timeout=self.ENTRY_TIMEOUT)
                entry.pop("dead", None)
                return ws, entry
            except Exception as exc:  # noqa: BLE001
                entry["dead"] = True
                self._log(f"[!] Точка входа {entry['ip']} не отвечает ({exc}).")
        return None, None

    def start(self) -> None:
        if not self.entries:
            raise RuntimeError("нет ни одной проверенной точки входа")
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(64)
        self._srv = srv
        self._running = True
        self._log(f"[*] Мост Telegram слушает {self.host}:{self.port}")
        threading.Thread(target=self._accept_loop, daemon=True,
                         name="tg-bridge").start()

    def stop(self) -> None:
        self._running = False
        if self._srv is not None:
            try:
                self._srv.close()
            except Exception:
                pass
            self._srv = None

    def _accept_loop(self) -> None:
        while self._running:
            try:
                client, _ = self._srv.accept()
            except Exception:
                break
            threading.Thread(target=self._session, args=(client,), daemon=True,
                             name="tg-sess").start()
        self._log("[*] Мост Telegram остановлен.")

    # -- одна сессия ------------------------------------------------------
    def _session(self, client: socket.socket) -> None:
        ws = None
        try:
            client.settimeout(20)
            target = self._socks_handshake(client)
            if target is None:
                return
            ip, port = target
            dc = dc_for_ip(ip)
            ws, entry = self._open_ws(dc)
            if ws is None:
                # честный отказ вместо молчаливого ожидания: клиент сразу
                # покажет «нет соединения», а не будет висеть до таймаута
                self._reply(client, 0x04)
                self._log("[!] Ни одна точка входа не поднялась — "
                          "нужно искать заново.")
                return
            self._reply(client, 0x00)
            self.stats["sessions"] += 1
            self.stats["active"] += 1
            self._log(f"[+] Telegram DC{dc} через {entry['ip']} (WebSocket)")
            self._pump(client, ws)
        except Exception as exc:  # noqa: BLE001
            self._log(f"[!] Сессия моста: {exc}")
        finally:
            self.stats["active"] = max(0, self.stats["active"] - 1)
            if ws is not None:
                ws.close()
            try:
                client.close()
            except Exception:
                pass

    def _socks_handshake(self, client) -> Optional[Tuple[str, int]]:
        head = client.recv(2)
        if len(head) < 2 or head[0] != 0x05:
            return None
        nmeth = head[1]
        client.recv(nmeth)
        client.sendall(b"\x05\x00")                  # без авторизации
        req = client.recv(4)
        if len(req) < 4 or req[1] != 0x01:           # только CONNECT
            self._reply(client, 0x07)
            return None
        atyp = req[3]
        if atyp == 0x01:
            ip = socket.inet_ntoa(client.recv(4))
        elif atyp == 0x03:
            ln = client.recv(1)[0]
            name = client.recv(ln).decode("latin1")
            try:
                ip = socket.gethostbyname(name)
            except Exception:
                self._reply(client, 0x04)
                return None
        else:
            self._reply(client, 0x08)
            return None
        port = struct.unpack("!H", client.recv(2))[0]
        if not is_telegram_ip(ip):
            # Это мост для Telegram, а не общий прокси: чужой трафик через
            # WebSocket дата-центра всё равно не пройдёт.
            #
            # Отказываем кодом 0x05 («в соединении отказано»), а НЕ 0x02
            # («запрещено правилами»). Разница не косметическая: 0x02 — это
            # ошибка политики, и клиент понимает её как «прокси настроен
            # неверно». Telegram на такое показывает окно и выключает прокси
            # целиком, хотя для его собственных дата-центров мост работает.
            # 0x05 — обычная сетевая неудача, после неё клиент просто
            # пробует иначе.
            self._reply(client, 0x05)
            return None
        return ip, port

    @staticmethod
    def _reply(client, code: int) -> None:
        try:
            client.sendall(bytes([0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        except Exception:
            pass

    def _pump(self, client: socket.socket, ws: WsConn) -> None:
        """Перекачка в обе стороны. Поток не трогаем — он зашифрован Telegram."""
        stop = threading.Event()

        def up():
            try:
                client.settimeout(None)
                while not stop.is_set():
                    data = client.recv(65536)
                    if not data:
                        break
                    ws.send_binary(data)
                    self.stats["bytes_up"] += len(data)
            except Exception:
                pass
            finally:
                stop.set()
                ws.close()

        t = threading.Thread(target=up, daemon=True, name="tg-up")
        t.start()
        try:
            while not stop.is_set():
                frame = ws.recv_binary()
                if frame is None:
                    break
                if frame:
                    client.sendall(frame)
                    self.stats["bytes_down"] += len(frame)
        except Exception:
            pass
        finally:
            stop.set()
            try:
                client.close()
            except Exception:
                pass
        t.join(timeout=1)


def socks_link(host: str, port: int) -> str:
    from urllib.parse import urlencode
    return "tg://socks?" + urlencode({"server": host, "port": int(port)})
