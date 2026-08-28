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

import glob
import json
import os
import re
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
    ports += [4444, 8388, 8389, 10086]    # Shadowsocks и разное
    ports += [7897, 7898]                 # Clash Verge (смешанный порт)
    ports += [40000, 40001]               # локальный прокси Cloudflare WARP
    ports += [2334, 8964, 9090, 6153]     # v2rayN, FlClash, панели управления
    ports += list(range(12080, 12086))    # Throne и наследники nekoray
    ports += [33210, 33211]               # Hiddify
    ports += list(range(8880, 8890))      # частый выбор «руками»
    seen, out = set(), []
    for p in ports:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


COMMON_PORTS: List[int] = _port_pool()

# Адреса дата-центров Telegram: по ним проверяем, что прокси реально уводит
# трафик наружу, а не просто отвечает на рукопожатие.
#
# Их несколько намеренно. Одного мало: конкретный дата-центр может быть недоступен
# с той стороны, куда ходит прокси, — и рабочий прокси был бы забракован.
TG_DCS = [
    ("149.154.167.51", 443),    # DC2, Амстердам
    ("149.154.175.50", 443),    # DC1, Майами
    ("91.108.56.130", 443),     # DC5, Сингапур
]
TG_DC = TG_DCS[0]               # прежнее имя — им пользуется старый код

# Порты, куда стучаться не надо: там системные службы Windows, прокси
# там не бывает, а рукопожатие им шлётся зря.
SKIP_PORTS = {135, 137, 138, 139, 445, 902, 912, 3389, 5985, 5986, 47001}

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


def _connect(host: str, port: int, timeout: float):
    """Соединение с любым адресом — и IPv4, и IPv6.

    socket.socket() по умолчанию умеет только IPv4, а клиенты нередко слушают
    на ::1 и больше нигде. create_connection разбирается сам.
    """
    return socket.create_connection((host, port), timeout=timeout)


def _listening(port: int, host: str = "127.0.0.1", timeout: float = 0.35) -> bool:
    try:
        s = _connect(host, port, timeout)
    except Exception:
        return False
    try:
        return True
    finally:
        try:
            s.close()
        except Exception:
            pass


def local_hosts() -> List[str]:
    """Адреса ЭТОЙ машины, на которых может висеть локальный прокси.

    Клиент, привязанный к 0.0.0.0, доступен и по 127.0.0.1 — но привязанный
    к конкретному адресу (адресу сетевой карты, интерфейсу WSL или Hyper-V)
    по петле НЕ доступен. Мы такой прокси видели в списке слушающих портов и
    всё равно не могли к нему подключиться.
    """
    out = ["127.0.0.1", "::1"]
    try:
        name = socket.gethostname()
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(name, None, fam)
            except Exception:                         # noqa: BLE001
                continue
            for info in infos:
                addr = info[4][0].split("%")[0]       # без зоны у IPv6
                # fe80:: — канальные адреса, без номера зоны к ним не
                # подключиться; 2001:0: — Teredo, туннель наружу. Прокси
                # ни там, ни там не живёт.
                if not addr or addr in out:
                    continue
                low = addr.lower()
                if low.startswith("fe80:") or low.startswith("2001:0:"):
                    continue
                out.append(addr)
    except Exception:                                 # noqa: BLE001
        pass
    return out[:8]                                    # больше и не бывает


# Сколько ждать ПЕРВОГО ответа. Местный прокси отвечает за миллисекунды;
# если за полторы секунды не ответил ничего — это не прокси, и ждать
# полный таймаут (да ещё трижды, по разу на дата-центр) незачем. Именно на
# этом поиск и застревал: молчащий порт стоил почти полминуты.
HELLO_TIMEOUT = 1.5
SILENT = "не отвечает на приветствие"


def _socks5_once(host: str, port: int, target: Tuple[str, int], timeout: float):
    try:
        s = _connect(host, port, timeout)
    except Exception:
        return False, "никто не слушает"
    try:
        s.settimeout(min(HELLO_TIMEOUT, timeout))
        s.sendall(b"\x05\x01\x00")                    # SOCKS5, без авторизации
        try:
            head = s.recv(2)
        except socket.timeout:
            return False, SILENT
        s.settimeout(timeout)
        if len(head) < 2 or head[0] != 0x05:
            return False, "это не SOCKS5"
        if head[1] == 0xFF:
            return False, "прокси требует логин и пароль"
        if head[1] != 0x00:
            return False, "прокси хочет другой способ входа"
        addr = target[0].encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr
                  + struct.pack("!H", target[1]))
        rep = s.recv(10)
        if len(rep) < 2:
            return False, "прокси не ответил"
        if rep[1] != 0x00:
            return False, ("до Telegram не доходит: "
                           + SOCKS5_ERRORS.get(rep[1], "код %d" % rep[1]))
        return True, "доходит до Telegram"
    except Exception as exc:                          # noqa: BLE001
        return False, type(exc).__name__
    finally:
        try:
            s.close()
        except Exception:
            pass


# Отказы, после которых пробовать другой дата-центр бессмысленно: дело не в
# том, куда мы идём, а в том, что на этом порту не тот протокол или нас не
# пускают вовсе.
_FINAL = ("это не SOCKS5", "это не HTTP-прокси", "никто не слушает",
          "прокси требует логин и пароль", "прокси хочет другой способ входа",
          SILENT)


def _probe_dcs(once, host: str, port: int, target, timeout: float):
    """Прогнать проверку по дата-центрам, пока один не отзовётся.

    Один-единственный адрес — лотерея: конкретный ДЦ может быть недоступен с
    той стороны, куда ходит прокси, и рабочий прокси окажется забракован.
    """
    targets = [target] if target else TG_DCS
    last = "не отвечает"
    for tgt in targets:
        ok, why = once(host, port, tgt, timeout)
        if ok:
            return True, why
        last = why
        if why in _FINAL:
            break
    return False, last


def probe_socks5(port: int, host: str = "127.0.0.1",
                 target: Optional[Tuple[str, int]] = None, timeout: float = 4.0):
    """SOCKS5 на порту? Возвращает (доходит ли до Telegram, пояснение)."""
    return _probe_dcs(_socks5_once, host, port, target, timeout)


def _http_once(host: str, port: int, target: Tuple[str, int], timeout: float):
    try:
        s = _connect(host, port, timeout)
    except Exception:
        return False, "никто не слушает"
    try:
        s.settimeout(min(HELLO_TIMEOUT, timeout))
        s.sendall(f"CONNECT {target[0]}:{target[1]} HTTP/1.1\r\n"
                  f"Host: {target[0]}:{target[1]}\r\n\r\n".encode())
        try:
            head = s.recv(64)
        except socket.timeout:
            return False, SILENT
        s.settimeout(timeout)
        if not head.startswith(b"HTTP/"):
            return False, "это не HTTP-прокси"
        code = head.split(b" ")[1:2]
        if code and code[0] == b"200":
            return True, "доходит до Telegram"
        if code and code[0] == b"407":
            return False, "прокси требует логин и пароль"
        return False, "прокси отказал: " + head.split(b"\r\n")[0].decode("latin1", "ignore")
    except Exception as exc:                          # noqa: BLE001
        return False, type(exc).__name__
    finally:
        try:
            s.close()
        except Exception:
            pass


def probe_http(port: int, host: str = "127.0.0.1",
               target: Optional[Tuple[str, int]] = None, timeout: float = 4.0):
    """HTTP-прокси с методом CONNECT — второй распространённый вид."""
    return _probe_dcs(_http_once, host, port, target, timeout)


def probe_socks4(port: int, host: str = "127.0.0.1",
                 target: Optional[Tuple[str, int]] = None, timeout: float = 4.0):
    """SOCKS4/4a. Найти его важно, но НЕ чтобы предложить.

    Telegram умеет ровно два вида прокси: SOCKS5 и HTTP. SOCKS4 он не умеет
    вовсе. Раньше такой порт просто молча не подходил, и человек видел
    «рабочего прокси нет», хотя прокси есть — просто не тот. Теперь он
    называется по имени, с объяснением.
    """
    tgt = target or TG_DCS[0]
    try:
        s = _connect(host, port, timeout)
    except Exception:
        return False, "никто не слушает"
    try:
        try:
            raw = socket.inet_aton(tgt[0])
        except OSError:
            return False, "не удалось разобрать адрес"
        s.settimeout(min(HELLO_TIMEOUT, timeout))
        s.sendall(b"\x04\x01" + struct.pack("!H", tgt[1]) + raw + b"\x00")
        try:
            rep = s.recv(8)
        except socket.timeout:
            return False, SILENT
        if len(rep) >= 2 and rep[0] == 0x00 and rep[1] in (0x5A, 0x5B, 0x5C, 0x5D):
            return True, "это SOCKS4 — Telegram работает только с SOCKS5 и HTTP"
        return False, "это не SOCKS4"
    except Exception as exc:                          # noqa: BLE001
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


def listening_ports(host: str = "127.0.0.1") -> List[int]:
    """Все локальные TCP-порты, которые кто-то СЛУШАЕТ.

    Угадывать порт по списку известных — заведомо проигрышная игра: у Clash
    Verge он 7897, у Throne свой, а человек мог поставить любой. Спрашиваем у
    системы напрямую (GetExtendedTcpTable), и тогда клиент находится, даже
    если про него никто никогда не слышал.

    Порты ниже 1024 отбрасываем: там системные службы, прокси там не живут.
    """
    import ctypes
    import ctypes.wintypes as wt

    if os.name != "nt":
        return []

    class _Row(ctypes.Structure):
        _fields_ = [("dwState", wt.DWORD), ("dwLocalAddr", wt.DWORD),
                    ("dwLocalPort", wt.DWORD), ("dwRemoteAddr", wt.DWORD),
                    ("dwRemotePort", wt.DWORD), ("dwOwningPid", wt.DWORD)]

    class _Row6(ctypes.Structure):
        _fields_ = [("ucLocalAddr", ctypes.c_byte * 16),
                    ("dwLocalScopeId", wt.DWORD), ("dwLocalPort", wt.DWORD),
                    ("dwState", wt.DWORD), ("dwOwningPid", wt.DWORD)]

    TCP_TABLE_OWNER_PID_LISTENER = 3
    AF_INET, AF_INET6 = 2, 23
    out: List[int] = []
    seen = set()
    try:
        iphlp = ctypes.windll.iphlpapi
    except Exception:                                 # noqa: BLE001
        return []

    # IPv4 и IPv6 отдельными таблицами. Клиент, слушающий только на ::1,
    # в таблице IPv4 не значится вовсе — а такие встречаются.
    for family, row_type in ((AF_INET, _Row), (AF_INET6, _Row6)):
        try:
            size = wt.DWORD(0)
            iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, family,
                                      TCP_TABLE_OWNER_PID_LISTENER, 0)
            if not size.value:
                continue
            buf = ctypes.create_string_buffer(size.value)
            if iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, family,
                                         TCP_TABLE_OWNER_PID_LISTENER, 0) != 0:
                continue
            count = ctypes.cast(buf, ctypes.POINTER(wt.DWORD))[0]
            rows = ctypes.cast(ctypes.byref(buf, ctypes.sizeof(wt.DWORD)),
                               ctypes.POINTER(row_type))
            for i in range(count):
                r = rows[i]
                # dwLocalPort лежит в сетевом порядке байт в младшем слове
                port = ((r.dwLocalPort & 0xFF) << 8) | ((r.dwLocalPort >> 8) & 0xFF)
                # Ниже 1024 живут системные службы, прокси там не бывает.
                if port < 1024 or port in SKIP_PORTS or port in seen:
                    continue
                seen.add(port)
                out.append(port)
        except Exception:                             # noqa: BLE001
            continue
    return sorted(out)


# Где клиенты держат свои настройки. Схемы у всех разные и меняются от версии
# к версии, поэтому разбираем не по схеме, а по смыслу: берём любое поле,
# в имени которого есть "port", со значением, похожим на номер порта.
_CONFIG_GLOBS = (
    "nekoray/config.json", "nekoray/*/config.json",
    "Throne/config.json", "throne/config.json",
    "v2rayN/guiNConfig.json", "v2rayN/guiConfig.json",
    "v2ray/config.json", "Xray/config.json", "xray/config.json",
    "sing-box/config.json", "sing-box/*.json",
    "Shadowsocks/gui-config.json",
    "clash/config.yaml", ".config/clash/config.yaml",
    "clash-verge/config.yaml", "io.github.clash-verge-rev.*/config.yaml",
    "io.github.clash-verge-rev.*/*/config.yaml",
    "mihomo/config.yaml", "FlClash/*.json",
    "hiddify*/*.json", "Hiddify*/*.json",
    "netch/*.json", "Netch/*.json",
)
_PORT_KEY = re.compile(r"port", re.I)
_YAML_PORT = re.compile(r"^\s*[\w.-]*port[\w.-]*\s*:\s*[\"']?(\d{2,5})", re.I | re.M)
_MAX_CONFIG_BYTES = 2 * 1024 * 1024


def _ports_from_json(node, out: set) -> None:
    """Обойти разобранный JSON и собрать всё, что похоже на номер порта."""
    if isinstance(node, dict):
        for key, val in node.items():
            if isinstance(val, int) and _PORT_KEY.search(str(key)):
                if 1024 <= val <= 65535:
                    out.add(val)
            elif isinstance(val, str) and val.isdigit() and _PORT_KEY.search(str(key)):
                num = int(val)
                if 1024 <= num <= 65535:
                    out.add(num)
            else:
                _ports_from_json(val, out)
    elif isinstance(node, list):
        for item in node:
            _ports_from_json(item, out)


def client_dirs() -> List[str]:
    """Папки, где лежат запущенные прокси-клиенты.

    NekoBox, v2rayN и Throne чаще всего ставят «портативно» — распакованной
    папкой, и настройки лежат рядом с exe, а не в AppData. Найти их можно
    только через запущенный процесс.
    """
    import ctypes
    import ctypes.wintypes as wt

    if os.name != "nt":
        return []
    PROCESS_QUERY_LIMITED = 0x1000
    k32 = ctypes.windll.kernel32
    out: List[str] = []
    try:
        from .anticheat import _process_names          # noqa: F401  (проверка наличия)
    except Exception:                                  # noqa: BLE001
        pass

    class _Entry(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
                    ("th32ProcessID", wt.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
                    ("th32ParentProcessID", wt.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_char * 260)]

    snap = k32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snap == -1:
        return []
    try:
        e = _Entry()
        e.dwSize = ctypes.sizeof(_Entry)
        ok = k32.Process32First(snap, ctypes.byref(e))
        while ok:
            stem = e.szExeFile.decode("cp1251", "replace").lower()
            stem = stem[:-4] if stem.endswith(".exe") else stem
            if any(key in stem for key in KNOWN_CLIENTS):
                h = k32.OpenProcess(PROCESS_QUERY_LIMITED, False, e.th32ProcessID)
                if h:
                    try:
                        buf = ctypes.create_unicode_buffer(1024)
                        size = wt.DWORD(1024)
                        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
                            folder = os.path.dirname(buf.value)
                            if folder and folder not in out:
                                out.append(folder)
                    finally:
                        k32.CloseHandle(h)
            ok = k32.Process32Next(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out[:6]


# Что искать в папке рядом с клиентом. Именами файлов не обойтись: у NekoBox
# порт лежит в config/groups/nekobox.json, у v2rayN — в guiNConfig.json рядом
# с exe, у Clash — в config.yaml. Поэтому обходим папку настроек вглубь на
# два уровня и смотрим всё, что похоже на настройки.
_LOCAL_GLOBS = ("*.json", "*.yaml", "*.yml",
                "config/*.json", "config/*.yaml", "config/*.yml",
                "config/*/*.json", "config/*/*.yaml",
                "data/*.json", "data/*/*.json",
                "profiles/*.json", "groups/*.json")
_MAX_LOCAL_FILES = 40


def config_ports() -> List[int]:
    """Порты, вычитанные из настроек прокси-клиентов.

    Зачем, если слушающие порты и так перечисляются: клиент может быть НЕ
    запущен (тогда мы хотя бы скажем, какой порт он занимал), а может слушать
    на адресе, до которого по петле не достучаться. И то и другое встречается.
    """
    bases = [os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA"),
             os.environ.get("ProgramData"), os.path.expanduser("~")]
    out: set = set()
    looked = 0
    # сперва рядом с самим клиентом: у портативных сборок настройки там
    for folder in client_dirs():
        seen_files = 0
        for pattern in _LOCAL_GLOBS:
            if seen_files >= _MAX_LOCAL_FILES:
                break
            for path in glob.glob(os.path.join(folder, pattern)):
                if seen_files >= _MAX_LOCAL_FILES:
                    break
                if os.path.isfile(path):
                    _harvest_config(path, out)
                    seen_files += 1
        looked += seen_files
    for base in bases:
        if not base or not os.path.isdir(base):
            continue
        for pattern in _CONFIG_GLOBS:
            if looked > 60:                           # не бродить по диску бесконечно
                break
            for path in glob.glob(os.path.join(base, pattern)):
                if looked > 60:
                    break
                try:
                    if os.path.getsize(path) > _MAX_CONFIG_BYTES:
                        continue
                    with open(path, "r", encoding="utf-8", errors="replace") as fh:
                        text = fh.read()
                except OSError:
                    continue
                looked += 1
                _harvest_text(path, text, out)
    return sorted(p for p in out if p not in SKIP_PORTS)


def _harvest_config(path: str, out: set) -> None:
    try:
        if os.path.getsize(path) > _MAX_CONFIG_BYTES:
            return
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            _harvest_text(path, fh.read(), out)
    except OSError:
        pass


def _harvest_text(path: str, text: str, out: set) -> None:
    if not path.lower().endswith((".yaml", ".yml")):
        try:
            _ports_from_json(json.loads(text), out)
            return
        except ValueError:
            pass                # не разобрался как JSON — ниже регуляркой
    for m in _YAML_PORT.finditer(text):
        num = int(m.group(1))
        if 1024 <= num <= 65535:
            out.add(num)


def env_endpoints() -> List[Tuple[str, int]]:
    """Прокси, прописанные в переменных окружения.

    Их выставляют и клиенты, и сам пользователь. Стоит почти ничего, а иногда
    это единственное место, где записан нестандартный порт.
    """
    out: List[Tuple[str, int]] = []
    for name in ("ALL_PROXY", "all_proxy", "HTTPS_PROXY", "https_proxy",
                 "HTTP_PROXY", "http_proxy", "SOCKS_PROXY", "socks_proxy"):
        raw = os.environ.get(name)
        if not raw:
            continue
        text = raw.split("://")[-1].split("@")[-1].strip().strip("/")
        if ":" not in text:
            continue
        host, _, port = text.rpartition(":")
        try:
            num = int(port)
        except ValueError:
            continue
        if 1 <= num <= 65535 and (host, num) not in out:
            out.append((host or "127.0.0.1", num))
    return out


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


# Какой адрес предпочесть, если клиент отозвался с нескольких. Петля надёжнее
# адреса сетевой карты: он может смениться, а прокси на нём — исчезнуть.
_HOST_RANK = {"127.0.0.1": 0, "::1": 1}


def candidates(host: str = "127.0.0.1") -> List[Tuple[str, int]]:
    """Все пары «адрес: порт», которые имеет смысл проверить.

    Источников намеренно много, и каждый закрывает свой промах остальных:

      * список известных портов — работает, даже когда клиент ещё не запущен;
      * реально слушающие порты (IPv4 и IPv6) — находит любой клиент, включая
        тот, о котором никто не слышал, и с портом, выставленным вручную;
      * настройки клиентов, в том числе портативных, — говорят порт даже у
        выключенного клиента и у того, кто слушает не на петле;
      * системный прокси и переменные окружения — там нередко записан
        нестандартный порт;
      * адреса этой машины — клиент, привязанный к адресу сетевой карты или
        к интерфейсу WSL, по 127.0.0.1 недоступен, и раньше мы его видели
        в списке портов, но подключиться не могли.
    """
    hosts = [host] + [h for h in local_hosts() if h != host]

    ports: List[int] = []
    seen: set = set()

    def add(value):
        try:
            num = int(value)
        except (TypeError, ValueError):
            return
        if 1 <= num <= 65535 and num not in seen and num not in SKIP_PORTS:
            seen.add(num)
            ports.append(num)

    for port in COMMON_PORTS:
        add(port)
    for port in listening_ports(host):
        add(port)
    for port in config_ports():
        add(port)

    pairs: List[Tuple[str, int]] = []
    pair_seen: set = set()

    def add_pair(h, port):
        key = (h, int(port))
        if key not in pair_seen:
            pair_seen.add(key)
            pairs.append(key)

    # Точечные адреса из настроек системы и окружения — их проверяем как есть,
    # даже если это не наша машина: человек их указал сам.
    sysp = system_proxy_endpoint()
    if sysp:
        add_pair(sysp[0], sysp[1])
    for h, port in env_endpoints():
        add_pair(h, port)

    for h in hosts:
        for port in ports:
            add_pair(h, port)
    return pairs


def scan(host: str = "127.0.0.1", stop=None, progress=None) -> Dict:
    """Полный поиск. Возвращает найденное, проверенное и объяснение.

    {"best": {...} | None, "all": [...], "clients": [...], "scanned": N}

    `stop` — threading.Event: если он взведён, проверка прекращается на
    ближайшем порту. Полное рукопожатие к каждому живому порту идёт секунды,
    и человек должен иметь возможность не ждать их все.

    `progress(сделано, всего, находка)` — вызывается на каждый проверенный
    порт, чтобы найденное показывалось по ходу, а не одним списком в конце.
    """
    def stopped():
        return bool(stop is not None and stop.is_set())

    if stopped():
        return {"best": None, "all": [], "clients": running_clients(),
                "scanned": 0, "alive": 0, "stopped": True}
    bridge = find_ws_bridge(host)
    found: List[dict] = []
    if bridge:
        found.append(bridge)
        if progress:
            try:
                progress(0, 0, bridge)
            except Exception:                         # noqa: BLE001
                pass

    pairs = candidates(host)

    # Сперва быстро отсеиваем закрытые порты: полноценное рукопожатие к
    # каждому кандидату заняло бы минуты. Закрытый порт на этой же машине
    # отвечает отказом не мгновенно (Windows успевает переспросить), поэтому
    # ждём мало и берём числом потоков.
    with ThreadPoolExecutor(max_workers=96) as ex:
        flags = list(ex.map(lambda hp: _listening(hp[1], hp[0]), pairs))
    alive = [hp for hp, ok in zip(pairs, flags) if ok]

    # Один и тот же клиент виден сразу с нескольких адресов: слушая 0.0.0.0,
    # он отвечает и по 127.0.0.1, и по [::], и по адресу сетевой карты.
    # Проверять его трижды незачем и показывать тремя строками тоже — на порт
    # оставляем один адрес, самый надёжный из тех, где он отозвался.
    best_host: Dict[int, str] = {}
    for h, port in alive:
        rank = _HOST_RANK.get(h, 2)
        if port not in best_host or rank < _HOST_RANK.get(best_host[port], 2):
            best_host[port] = h
    todo = [(h, port) for h, port in alive
            if best_host.get(port) == h
            and not (bridge and port == bridge["port"] and h == bridge["host"])]

    def _probe(pair) -> dict:
        h, port = pair
        where = f"[{h}]:{port}" if ":" in h else f"{h}:{port}"
        # Три протокола проверяем ОДНОВРЕМЕННО, а не по очереди: соединения
        # независимы, а последовательно молчащий порт стоил бы трёх таймаутов
        # подряд. Порядок предпочтения задаётся ниже, при разборе ответов.
        with ThreadPoolExecutor(max_workers=3) as sub:
            f5 = sub.submit(probe_socks5, port, h)
            fh = sub.submit(probe_http, port, h)
            f4 = sub.submit(probe_socks4, port, h)
            (ok, why), (ok2, why2), (ok3, why3) = f5.result(), fh.result(), f4.result()
        if ok:
            return {"host": h, "port": port, "kind": "socks5",
                    "note": why, "title": f"SOCKS5 {where}"}
        if ok2:
            return {"host": h, "port": port, "kind": "http",
                    "note": why2, "title": f"HTTP-прокси {where}"}
        # SOCKS4 Telegram не умеет вовсе — но молчать о нём хуже, чем сказать:
        # иначе человек видит «прокси нет», хотя прокси есть, просто не тот.
        if ok3:
            return {"host": h, "port": port, "kind": "socks4", "broken": True,
                    "note": why3, "title": f"SOCKS4 {where}"}
        # порт живой, но не прокси или не пускает — сохраним для объяснения
        note = why
        if note in ("никто не слушает", SILENT) and why2 not in ("никто не слушает",):
            note = why2 if why2 != SILENT else note
        return {"host": h, "port": port, "kind": "", "broken": True,
                "note": note, "title": where}

    # Проверяем ПАРАЛЛЕЛЬНО и докладываем о каждой находке сразу. Раньше порты
    # перебирались по одному, а результат человек видел только в самом конце:
    # со стороны это выглядело как «висит и ничего не делает».
    if todo:
        done = 0
        with ThreadPoolExecutor(max_workers=min(24, len(todo))) as ex:
            futs = [ex.submit(_probe, pair) for pair in todo]
            for fut in futs:
                if stopped():
                    break
                try:
                    item = fut.result()
                except Exception:                     # noqa: BLE001
                    continue
                done += 1
                found.append(item)
                if progress:
                    try:
                        progress(done, len(todo), item)
                    except Exception:                 # noqa: BLE001
                        pass

    working = [f for f in found if not f.get("broken")]
    # HTTP-прокси годится, но добавлять его придётся руками, поэтому он
    # последний: при прочих равных предлагаем то, что ставится в одно нажатие.
    working.sort(key=lambda f: KIND_ORDER.get(f.get("kind"), 9))
    return {"best": working[0] if working else None,
            "all": found,
            "clients": running_clients(),
            # порты из настроек установленных клиентов: если ничего не нашлось,
            # по ним видно, что клиент есть, просто не запущен
            "configured": config_ports(),
            "scanned": len(pairs),
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


def telegram_exe() -> Optional[str]:
    """Путь к Telegram Desktop на этой машине, если он установлен.

    Нужен, чтобы отдать ссылку tg:// программе НАПРЯМУЮ. Через os.startfile
    Windows показывает свой выбор приложения («Как вы хотите открыть эту
    ссылку?»), и если это окно свернуть или закрыть, не выбрав ничего, ссылка
    считается отменённой. Telegram при этом успевает получить отмену на уже
    открытом диалоге прокси и выключает его — со стороны выглядит так, будто
    программа сама сбросила настройку.
    """
    if os.name != "nt":
        return None
    # Сначала спрашиваем систему: какой командой она открывает tg://
    try:
        import winreg
        for root, path in ((winreg.HKEY_CURRENT_USER,
                            r"Software\Classes	desktop.tg\shell\open\command"),
                           (winreg.HKEY_CLASSES_ROOT,
                            r"tdesktop.tg\shell\open\command"),
                           (winreg.HKEY_CLASSES_ROOT, r"tg\shell\open\command")):
            try:
                with winreg.OpenKey(root, path) as key:
                    cmd, _ = winreg.QueryValueEx(key, "")
            except OSError:
                continue
            exe = _exe_from_command(str(cmd or ""))
            if exe:
                return exe
    except Exception:                                 # noqa: BLE001
        pass
    # Не нашлось в реестре — смотрим обычные места установки
    for base in (os.environ.get("APPDATA"), os.environ.get("LOCALAPPDATA"),
                 os.environ.get("ProgramFiles"),
                 os.environ.get("ProgramFiles(x86)")):
        if not base:
            continue
        cand = os.path.join(base, "Telegram Desktop", "Telegram.exe")
        if os.path.isfile(cand):
            return cand
    return None


def _exe_from_command(cmd: str) -> Optional[str]:
    """Вытащить путь к программе из строки запуска реестра."""
    cmd = cmd.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        exe = cmd[1:end] if end > 0 else ""
    else:
        exe = cmd.split(" ")[0]
    exe = os.path.expandvars(exe)
    return exe if exe and os.path.isfile(exe) else None


def open_link(link: str) -> Tuple[bool, str]:
    """Отдать ссылку tg:// Telegram'у. (получилось, чем именно)"""
    exe = telegram_exe()
    if exe:
        try:
            import subprocess
            subprocess.Popen([exe, "--", link], close_fds=True)
            return True, os.path.basename(exe)
        except Exception:                             # noqa: BLE001
            pass
    try:
        os.startfile(link)                            # noqa: S606 — ссылка tg://
        return True, "системный обработчик"
    except Exception as exc:                          # noqa: BLE001
        return False, str(exc)


# Что предпочесть, если рабочих нашлось несколько. Порядок не вкусовой:
#   mtproto — поднят ровно ради Telegram, добавляется одной ссылкой;
#   socks5  — Telegram умеет добавлять его ссылкой tg://socks;
#   http    — ссылки для него НЕ существует, только руками в настройках.
# Порядок предпочтения. «own» — наш собственный мост: он рабочий, но
# неполный (возит только адреса Telegram), поэтому уступает любому
# настоящему прокси и идёт последним среди годных.
KIND_ORDER = {"mtproto": 0, "socks5": 1, "http": 2, "own": 5, "socks4": 8}


def link_for(found: dict) -> str:
    """Ссылка tg:// для находки. Пусто — значит ссылкой её не добавить.

    У Telegram есть ровно две схемы прокси: tg://proxy (MTProto) и tg://socks
    (SOCKS5). Для HTTP-прокси схемы нет вообще.

    Раньше сюда попадал любой вид, и HTTP-прокси уходил в Telegram под видом
    SOCKS5. Telegram честно пытался говорить с ним по SOCKS5, получал в ответ
    HTTP и показывал «The proxy you are using is not configured correctly and
    will be disabled» — после чего ВЫКЛЮЧАЛ прокси. Со стороны это выглядело
    так, будто программа сама его отключает.
    """
    kind = found.get("kind")
    if kind == "mtproto":
        return tg_mtproto_link(found["host"], found["port"], found.get("secret", ""))
    if kind == "socks5":
        return tg_socks_link(found["host"], found["port"])
    return ""
