"""
Обновление RuFreedom через релизы GitHub.

Как это устроено и почему именно так:

* Скачиваем ТОЛЬКО с github.com и *.githubusercontent.com. Ссылку на файл даёт
  сам API релиза, но проверяем каждый переход: подменённый редирект увёл бы
  загрузку на чужой сервер, а этот файл мы потом запускаем.
* Проверяем размер и, если GitHub его сообщил, sha256. Оборванная закачка не
  должна превратиться в неработающую программу.
* Подменяем файл переименованием, без .bat-помощников: работающий exe в Windows
  переименовать можно. Старый уходит в сторону, новый встаёт на его место, и при
  малейшей осечке всё возвращается обратно.
* Ставит обновление человек: ничего из этого не запускается само, только после
  согласия в окне.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

# Здесь живут релизы. Меняется одной строкой, если репозиторий переедет.
OWNER = "LEGionWAR7"
REPO = "RuFreedom"

# ЕДИНСТВЕННОЕ место, где живёт номер версии. Паспорт exe
# (version_info.txt) собирается из него при сборке, руками его
# править не надо -- иначе номера разъедутся.
VERSION = "0.2.0"

API_URL = f"https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
RELEASES_URL = f"https://github.com/{OWNER}/{REPO}/releases"

# Откуда вообще позволено качать. Всё остальное — отказ.
ALLOWED_HOSTS = ("github.com", "api.github.com", "objects.githubusercontent.com",
                 "release-assets.githubusercontent.com", "codeload.github.com")

_TIMEOUT = 10.0
_UA = f"{REPO}/{VERSION}"
_CHUNK = 256 * 1024
MAX_BYTES = 200 * 1024 * 1024        # больше 200 МБ наша программа не весит


# --- версии ----------------------------------------------------------------
def parse_version(text: str) -> Tuple[int, ...]:
    """«v1.2.3-beta» -> (1, 2, 3). Непонятное превращается в (0,)."""
    m = re.search(r"(\d+(?:\.\d+)*)", text or "")
    if not m:
        return (0,)
    return tuple(int(p) for p in m.group(1).split("."))


def _cmp(a: str, b: str) -> int:
    x, y = parse_version(a), parse_version(b)
    n = max(len(x), len(y))
    x += (0,) * (n - len(x))
    y += (0,) * (n - len(y))
    return (x > y) - (x < y)


def is_newer(latest: str, current: str = VERSION) -> bool:
    return _cmp(latest, current) > 0


def min_version(notes: str) -> str:
    """Минимальная поддерживаемая версия из описания релиза.

    В тексте релиза можно написать строку вида «min: 0.3.0» (или
    «минимальная версия: 0.3.0»). Всё, что старее, снято с поддержки.
    Строки нет — требованием считается сам факт нового релиза.
    """
    m = re.search(r"(?:min|min-version|минимальная\s+версия)\s*[:=]\s*v?(\d+(?:\.\d+)*)",
                  notes or "", re.IGNORECASE)
    return m.group(1) if m else ""


# --- проверка --------------------------------------------------------------
def _api(url: str, timeout: float = _TIMEOUT) -> Dict:
    req = urllib.request.Request(
        url, headers={"Accept": "application/vnd.github+json", "User-Agent": _UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def pick_asset(data: Dict) -> Optional[Dict]:
    """Файл релиза, которым обновляемся: наш .exe."""
    best = None
    for a in data.get("assets") or ():
        name = (a.get("name") or "").lower()
        if not name.endswith(".exe"):
            continue
        if REPO.lower() in name:
            return a
        best = best or a
    return best


def check(timeout: float = _TIMEOUT) -> Dict:
    """Спросить у GitHub последний релиз.

    Ключи всегда одни и те же — интерфейсу не приходится гадать.
    `required` = текущая версия снята с поддержки.
    """
    out = {"current": VERSION, "latest": "", "newer": False, "required": False,
           "url": RELEASES_URL, "notes": "", "error": "",
           "asset": "", "size": 0, "sha256": ""}
    try:
        data = _api(API_URL, timeout)
    except urllib.error.HTTPError as exc:
        out["error"] = "релизов пока нет" if exc.code == 404 else f"GitHub: {exc.code}"
        return out
    except Exception as exc:                       # noqa: BLE001
        out["error"] = str(exc) or "нет связи с GitHub"
        return out

    tag = (data.get("tag_name") or data.get("name") or "").strip()
    if not tag:
        out["error"] = "релиз без номера версии"
        return out
    notes = (data.get("body") or "").strip()
    out["latest"] = tag
    out["newer"] = is_newer(tag)
    out["url"] = data.get("html_url") or RELEASES_URL
    out["notes"] = notes[:600]

    if out["newer"]:
        floor = min_version(notes)
        # без явной планки требованием считается любой новый релиз
        out["required"] = _cmp(VERSION, floor) < 0 if floor else True

    asset = pick_asset(data)
    if asset:
        out["asset"] = asset.get("browser_download_url", "")
        out["size"] = int(asset.get("size") or 0)
        digest = str(asset.get("digest") or "")
        if digest.lower().startswith("sha256:"):
            out["sha256"] = digest.split(":", 1)[1].strip().lower()
    return out


# --- загрузка --------------------------------------------------------------
def _host_ok(url: str) -> bool:
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError:
        return False
    if u.scheme != "https":
        return False
    host = (u.hostname or "").lower()
    return host in ALLOWED_HOSTS or host.endswith(".githubusercontent.com")


class _StrictRedirect(urllib.request.HTTPRedirectHandler):
    """Переход разрешён только внутрь GitHub и только по https."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _host_ok(newurl):
            raise urllib.error.URLError(f"перенаправление за пределы GitHub: {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _quiet_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def download(url: str, dest: str, progress: Optional[Callable[[int, int], None]] = None,
             expect_size: int = 0, sha256: str = "", timeout: float = 30.0) -> str:
    """Скачать файл релиза. Пустая строка = успех, иначе причина отказа."""
    if not _host_ok(url):
        return "ссылка ведёт не на GitHub — скачивать не буду"
    opener = urllib.request.build_opener(_StrictRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": _UA,
                                               "Accept": "application/octet-stream"})
    tmp = dest + ".part"
    got = 0
    h = hashlib.sha256()
    try:
        with opener.open(req, timeout=timeout) as resp:
            if not _host_ok(resp.geturl()):
                return "загрузка ушла на чужой сервер"
            total = expect_size or int(resp.headers.get("Content-Length") or 0)
            if total and total > MAX_BYTES:
                return "файл подозрительно большой"
            with open(tmp, "wb") as fh:
                while True:
                    chunk = resp.read(_CHUNK)
                    if not chunk:
                        break
                    got += len(chunk)
                    if got > MAX_BYTES:
                        raise ValueError("файл подозрительно большой")
                    h.update(chunk)
                    fh.write(chunk)
                    if progress:
                        try:
                            progress(got, total)
                        except Exception:          # noqa: BLE001
                            pass
    except Exception as exc:                       # noqa: BLE001
        _quiet_remove(tmp)
        return str(exc) or "не удалось скачать"

    if expect_size and got != expect_size:
        _quiet_remove(tmp)
        return f"размер не совпал: {got} вместо {expect_size}"
    if sha256 and h.hexdigest().lower() != sha256:
        _quiet_remove(tmp)
        return "контрольная сумма не совпала — файл повреждён или подменён"
    if got < 1024:
        _quiet_remove(tmp)
        return "файл пустой"
    try:
        os.replace(tmp, dest)
    except OSError as exc:
        _quiet_remove(tmp)
        return f"не удалось сохранить: {exc}"
    return ""


# --- установка -------------------------------------------------------------
def staging_path() -> str:
    d = os.path.join(tempfile.gettempdir(), f"{REPO}-update")
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, f"{REPO}.new.exe")


def old_path() -> str:
    return os.path.splitext(sys.executable)[0] + ".old.exe"


def cleanup_old() -> None:
    """Убрать отодвинутый прошлый exe. Зовётся на старте, тихо."""
    if not getattr(sys, "frozen", False):
        return
    _quiet_remove(old_path())


def install_and_restart(new_exe: str) -> str:
    """Поставить скачанный файл на место текущего и перезапуститься.

    Возвращает причину отказа; при успехе — пустую строку, и вызывающий
    обязан завершить процесс. Работающий exe в Windows нельзя перезаписать,
    но МОЖНО переименовать: старый уходит в сторону, новый встаёт на его
    место. Если второй шаг не удался, первый откатывается — программа не
    должна исчезнуть с диска из-за неудачного обновления.
    """
    if not getattr(sys, "frozen", False):
        return "обновление работает только в собранной программе"
    if not os.path.isfile(new_exe):
        return "скачанный файл не найден"
    cur = sys.executable
    old = old_path()
    _quiet_remove(old)
    try:
        os.replace(cur, old)
    except OSError as exc:
        return f"не удалось отодвинуть старую версию: {exc}"
    try:
        os.replace(new_exe, cur)
    except OSError as exc:
        try:                                   # откат: возвращаем как было
            os.replace(old, cur)
        except OSError:
            pass
        return f"не удалось поставить новую версию: {exc}"

    flags = (getattr(subprocess, "DETACHED_PROCESS", 0)
             | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    try:
        subprocess.Popen([cur], close_fds=True, creationflags=flags)
    except Exception as exc:                       # noqa: BLE001
        return f"новая версия установлена, но не запустилась: {exc}"
    return ""


def asset_urls(data: Dict) -> List[str]:
    return [a.get("browser_download_url", "")
            for a in (data.get("assets") or ()) if a.get("browser_download_url")]
