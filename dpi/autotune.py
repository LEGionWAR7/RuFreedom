"""
Автоподбор обхода DPI — отдельно для каждой группы сервисов.

Идея: по очереди включаем комбинации техник и проверяем настоящим TLS-подключением,
до каких сервисов удаётся достучаться. Раньше победитель был ОДИН на всех, и
приходилось выбирать, кем пожертвовать: то, что пробивает Discord, не пробивает
Epic. Теперь каждая группа забирает первую комбинацию, которая сработала именно
для неё, а перебор идёт от дешёвых техник к тяжёлым — значит выигрывает самая
щадящая из работающих, и тай-брейк не нужен.

Проверка хоста = полное TLS-рукопожатие с указанием SNI. При блокировке по SNI
соединение рвётся (RST/timeout) на ClientHello, и рукопожатие не проходит.
"""

from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from . import services
from .config import DEFAULT_FAKE_SNI, Profile

# Хост, который заведомо не блокируют. Нужен, чтобы отличить «сервис заблокирован»
# от «интернет отвалился целиком» — без этого сторож перебирал бы стратегии, пока
# у пользователя просто нет сети.
CONTROL_HOST = "www.microsoft.com"

MAX_WORKERS = 16


# --- комбинации ------------------------------------------------------------
# Порядок ВАЖЕН: от дешёвых (мало внедрённых пакетов) к тяжёлым. Группа
# закрепляет за собой первую сработавшую, поэтому порядок и есть правило выбора.
#
# `pos2` — разрез на втором байте: он рвёт заголовок TLS-записи, и многие DPI
# после этого вообще не опознают в потоке TLS. Именно это чаще всего и пробивает
# YouTube с Discord.
CANDIDATES: List[Dict] = [
    # -- ПЕРЕКРЫТИЕ ЦЕЛЫМ ClientHello. Идёт первым не по традиции: именно эта
    #    комбинация (multisplit, разрез на 1-м байте, перекрытие 568 байт с
    #    подставным ClientHello) пробивает Discord и YouTube там, где обычное
    #    разрезание не даёт вообще ничего. Ничего лишнего в сеть не внедряется:
    #    сервер отбрасывает перекрытие сам, по правилам TCP.
    # Проверено замером на реальной сети: это пробивает Discord (6/6) и
    # www.youtube.com (3/3). Держим первыми — подбор находит их за полминуты.
    {"label": "перекрытие 568 @1",     "strategy": "multisplit",    "split": "pos1",       "fooling": "none", "segs": 2, "ovl": 568},
    {"label": "multidisorder x3 @имя", "strategy": "multidisorder", "split": "host-start", "fooling": "none", "segs": 3},
    # Разрез после первой буквы имени. Замером: единственное, чем берётся
    # youtubei.googleapis.com — а через него грузятся Shorts и лента (4/4,
    # без обхода 0/4). Соседний host-start его НЕ берёт, разница именно в байте.
    {"label": "multidisorder x3 @1-я буква", "strategy": "multidisorder", "split": "first-char", "fooling": "none", "segs": 3},
    {"label": "multidisorder x4 @1-я буква", "strategy": "multidisorder", "split": "first-char", "fooling": "none", "segs": 4},
    {"label": "multidisorder x5 @имя",     "strategy": "multidisorder", "split": "host-start", "fooling": "none", "segs": 5},
    {"label": "перекрытие 681 @1",     "strategy": "multisplit",    "split": "pos1",       "fooling": "none", "segs": 2, "ovl": 681},
    {"label": "перекрытие 568 @2",     "strategy": "multisplit",    "split": "pos2",       "fooling": "none", "segs": 2, "ovl": 568},
    {"label": "перекрытие 336 @1",     "strategy": "split",         "split": "pos1",       "fooling": "none", "ovl": 336},
    # Ровно то, что в конфиге zapret стоит для списка Google (то есть YouTube):
    # перекрытие 681 подставным ClientHello плюс обнулённый IP ID.
    {"label": "Google: ovl681 + id0",  "strategy": "multisplit",    "split": "pos1",       "fooling": "none", "segs": 2, "ovl": 681, "id0": True},
    {"label": "Google: ovl568 + id0",  "strategy": "multisplit",    "split": "pos1",       "fooling": "none", "segs": 2, "ovl": 568, "id0": True},
    {"label": "Google: ovl681 @2 +id0","strategy": "multisplit",    "split": "pos2",       "fooling": "none", "segs": 2, "ovl": 681, "id0": True},

    # -- Разрез по домену ВТОРОГО УРОВНЯ. Для www.youtube.com это середина
    #    слова «youtube». Так режет zapret по умолчанию, и у нас этого не было
    #    вовсе: мы резали либо от начала пакета, либо от начала имени, а DPI
    #    ищет имя целиком — рвать его надо внутри, а не по краям.
    {"label": "перекрытие 652 @2",     "strategy": "multisplit",    "split": "pos2",       "fooling": "none", "segs": 2, "ovl": 652},
    {"label": "multisplit @середине имени",   "strategy": "multisplit",    "split": "midsld", "fooling": "none", "segs": 2},
    {"label": "multidisorder x3 @середине",   "strategy": "multidisorder", "split": "midsld", "fooling": "none", "segs": 3},
    {"label": "перекрытие 568 @середине",     "strategy": "multisplit",    "split": "midsld", "fooling": "none", "segs": 2, "ovl": 568},
    {"label": "multidisorder x3 @конец имени","strategy": "multidisorder", "split": "endsld", "fooling": "none", "segs": 3},

    # -- Подделки, назвавшиеся web.vk.me. Смысл: DPI пропускает не глядя то,
    #    что держит в белом списке, а vk.me там есть почти у всех российских
    #    провайдеров — в отличие от гугла, который сам под фильтром.
    {"label": "подделка vk.me x6 +ttl1",  "strategy": "fake",         "split": "midsld", "fooling": "ttl", "ttl": 1, "fakes": 6, "sni": "web.vk.me"},
    {"label": "подделка vk.me x2 +badseq","strategy": "fakedisorder", "split": "midsld", "fooling": "badseq", "fakes": 2, "sni": "web.vk.me"},
    {"label": "внутри vk.me x6 @середине","strategy": "fakedsplit",   "split": "midsld", "fooling": "badseq", "fakes": 6, "sni": "web.vk.me"},
    {"label": "перекрытие vk.me 568 @1",  "strategy": "multisplit",   "split": "pos1",   "fooling": "none", "segs": 2, "ovl": 568, "sni": "web.vk.me"},
    {"label": "подделка ya.ru x6 +ttl1",  "strategy": "fake",         "split": "midsld", "fooling": "ttl", "ttl": 1, "fakes": 6, "sni": "ya.ru"},

    # -- лёгкие: только режем пакет, ничего не внедряем. Работают лишь там, где
    #    DPI смотрит на каждый сегмент отдельно; такой сейчас редкость, но
    #    проверка дешёвая, а выигрыш — самый щадящий режим
    {"label": "split @2",              "strategy": "split",         "split": "pos2",       "fooling": "none"},
    {"label": "disorder @2",           "strategy": "disorder",      "split": "pos2",       "fooling": "none"},
    {"label": "multidisorder x3",      "strategy": "multidisorder", "split": "host-start", "fooling": "none", "segs": 3},

    # -- подделка ПЕРЕД данными. badseq не зависит ни от числа хопов, ни от
    #    железа провайдера, поэтому идёт первым
    {"label": "fake+badseq @2",        "strategy": "fakedisorder",  "split": "pos2",       "fooling": "badseq"},
    {"label": "fake+badseq @имя",      "strategy": "fake",          "split": "host-start", "fooling": "badseq"},
    {"label": "fake+badsum @2",        "strategy": "fakedisorder",  "split": "pos2",       "fooling": "badsum"},

    # -- подделка МЕЖДУ кусками: против DPI, который собирает поток обратно,
    #    это главный приём — склейка у него получается битой
    {"label": "подделка внутри+badseq","strategy": "fakedsplit",    "split": "pos2",       "fooling": "badseq"},
    {"label": "подделка внутри, обр.", "strategy": "fakeddisorder", "split": "pos2",       "fooling": "badseq"},
    {"label": "подделка внутри @имя",  "strategy": "fakedsplit",    "split": "host-start", "fooling": "badseq"},

    # -- TTL: главный источник «у одного работает, у другого нет». 1-2 когда DPI
    #    на первом хопе провайдера, 5-8 когда он глубже в транзите
    {"label": "fake+ttl2 @2",          "strategy": "fakedisorder",  "split": "pos2",       "fooling": "ttl", "ttl": 2},
    {"label": "fake+ttl3 @2",          "strategy": "fakedisorder",  "split": "pos2",       "fooling": "ttl", "ttl": 3},
    {"label": "fake+ttl4 @2",          "strategy": "fakedisorder",  "split": "pos2",       "fooling": "ttl", "ttl": 4},
    {"label": "fake+ttl1 @имя",        "strategy": "fake",          "split": "host-start", "fooling": "ttl", "ttl": 1},
    {"label": "fake+ttl6 @2",          "strategy": "fakedisorder",  "split": "pos2",       "fooling": "ttl", "ttl": 6},
    {"label": "fake+ttl8 @2",          "strategy": "fakedisorder",  "split": "pos2",       "fooling": "ttl", "ttl": 8},
    {"label": "внутри+ttl2 @2",        "strategy": "fakedsplit",    "split": "pos2",       "fooling": "ttl", "ttl": 2},
    {"label": "внутри+ttl5 @имя",      "strategy": "fakeddisorder", "split": "host-start", "fooling": "ttl", "ttl": 5},

    # -- тяжёлые: несколько подделок подряд, комбинированный обман, перекрытие
    {"label": "fake x2 +badseq @2",    "strategy": "fakedisorder",  "split": "pos2",       "fooling": "badseq",    "fakes": 2},
    {"label": "внутри x2 +перекрытие", "strategy": "fakeddisorder", "split": "pos2",       "fooling": "badseq",    "fakes": 2, "ovl": 16},
    {"label": "fake x2 +ttlbadsum3",   "strategy": "fakedisorder",  "split": "pos2",       "fooling": "ttlbadsum", "ttl": 3, "fakes": 2},
    {"label": "внутри x2 +ttlbadsum1", "strategy": "fakedsplit",    "split": "pos1",       "fooling": "ttlbadsum", "ttl": 1, "fakes": 2},
    {"label": "fake x4 +badseq @3",    "strategy": "fakedisorder",  "split": "pos3",       "fooling": "badseq",    "fakes": 4, "ovl": 336},
    {"label": "внутри x4 +ttl2 @имя",  "strategy": "fakeddisorder", "split": "host-start", "fooling": "ttl", "ttl": 2, "fakes": 4},
    {"label": "внутри+перекрытие 568", "strategy": "fakedsplit",    "split": "pos1",       "fooling": "badseq",    "fakes": 2, "ovl": 568},
]


def candidate_to_profile(c: Dict, quic_mode: str = "drop",
                         udp_fake: bool = False) -> Profile:
    """Единственное место, где имена ключей комбинации превращаются в поля профиля."""
    return Profile(
        strategy=c["strategy"],
        split_mode=c.get("split", "pos2"),
        fooling=c.get("fooling", "badseq"),
        fake_ttl=int(c.get("ttl", 4)),
        fake_count=int(c.get("fakes", 1)),
        seg_count=int(c.get("segs", 3)),
        seqovl=int(c.get("ovl", 0)),
        ip_id_zero=bool(c.get("id0", False)),
        fake_sni=c.get("sni") or DEFAULT_FAKE_SNI,
        quic_mode=quic_mode,
        udp_fake=udp_fake,
    ).normalized()


def label_of(c: Dict) -> str:
    return c["label"]


# --- проверки --------------------------------------------------------------
def test_host(host: str, timeout: float = 4.0) -> bool:
    """True, если удалось завершить TLS-рукопожатие к host:443."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def probe_targets(group_ids) -> List[Tuple[str, str]]:
    """[(группа, хост)] для перечисленных групп."""
    out: List[Tuple[str, str]] = []
    for gid in group_ids:
        for host in services.probe_hosts(gid):
            out.append((gid, host))
    return out


# Сетка для добора: когда список готовых комбинаций не дал ничего, перебираем
# семейство multi-режимов по числу сегментов и точке разреза. Именно так был
# найден обход для youtubei.googleapis.com — разница между `host-start` и
# `first-char` всего в один байт, и угадать её нельзя, только перебрать.
GRID_STRATEGIES = ["multidisorder", "multisplit"]
GRID_SEGMENTS = [3, 4, 5, 6]
# Точек разреза больше, чем кажется нужным, и это осознанно: у одного хоста
# сработал `host-start`, у соседнего — только `first-char`, разница в один байт.
# Поэтому проходим окрестность имени по шагу, а не наугад.
GRID_SPLITS = ["first-char", "host-start", "host+1", "host+2", "host+3",
               "midsld", "sld", "endsld",
               "mid-host", "host-end", "pos1", "pos2", "pos3", "pos5", "pos8"]
# Перекрытие подставным ClientHello: им берётся Discord, поэтому в сетке оно
# тоже есть — но вторым проходом, чтобы не удлинять первый.
GRID_OVERLAPS = [0, 568]


def grid_candidates() -> List[Dict]:
    """Комбинации добора — их пробуют, если список выше не сработал.

    Порядок продуман, потому что он и есть время ожидания. Решает почти всегда
    ТОЧКА РАЗРЕЗА, а число сегментов — почти никогда: у одного хоста берёт
    `first-char`, у соседнего только `host-start`, разница в один байт, а
    x3 против x5 меняет исход куда реже. Поэтому идём от грубого к точному:
    сначала все 15 точек разреза обеими стратегиями при x3 — это 30 проверок,
    примерно две минуты, и они покрывают главное; и только потом добираем
    число сегментов и перекрытие.

    Раньше порядок был обратный (сначала все сегменты одной стратегии), и до
    второй стратегии перебор доходил только на 61-й проверке — четыре минуты
    впустую, если ответ лежал именно там.
    """
    out: List[Dict] = []
    for ovl in GRID_OVERLAPS:
        for segs in GRID_SEGMENTS:
            for strat in GRID_STRATEGIES:
                for split in GRID_SPLITS:
                    tail = f" +перекрытие" if ovl else ""
                    out.append({
                        "label": f"сетка: {strat} x{segs} {split}{tail}",
                        "strategy": strat, "split": split,
                        "fooling": "none", "segs": segs, "ovl": ovl,
                        "grid": True,
                    })
    return out


def test_host_repeat(host: str, tries: int = 2, timeout: float = 4.0) -> bool:
    """Хост считается открытым, только если рукопожатие прошло ВСЕ разы.

    Блокировка мигает: одиночная удача случается и без обхода, и раньше подбор
    на неё покупался — закреплял стратегию, которая на деле ничего не давала.
    """
    for _ in range(max(1, tries)):
        if not test_host(host, timeout):
            return False
    return True


def test_probes(group_ids, timeout: float = 4.0, tries: int = 2) -> Dict[str, bool]:
    """{группа: доступны ли ВСЕ её проверочные хосты}.

    Требование «все» намеренно строгое: у Discord и YouTube инфраструктура
    разнесена (шлюз и CDN режут по-разному), и достаточно, чтобы отвалилась
    одна половина, — сервис уже не работает.

    Сюда идут ТОЛЬКО постоянные проверочные хосты, и добавлять к ним
    подсмотренные в трафике имена нельзя. Такие имена (rr4---sn-… у YouTube,
    номерные у discord.media) живут одну сессию, а раз пройти обязаны все, —
    одно протухшее заваливает подряд всех кандидатов. Для подсмотренных имён
    есть score_probes: там они меняют место в очереди, а не выкидывают из неё.
    """
    targets = probe_targets(group_ids)
    if not targets:
        return {}
    results: Dict[str, bool] = {gid: True for gid, _ in targets}
    workers = max(1, min(MAX_WORKERS, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [(gid, ex.submit(test_host_repeat, host, tries, timeout))
                for gid, host in targets]
        for gid, fut in futs:
            try:
                ok = fut.result()
            except Exception:
                ok = False
            results[gid] = results[gid] and ok
    return results


def score_probes(group_ids, timeout: float = 4.0, rounds: int = 3,
                 extra: Optional[Dict[str, list]] = None) -> Dict[str, tuple]:
    """{группа: (удачных рукопожатий, всего)} — оценка вместо «да/нет».

    Нужна для финала подбора. «Прошло/не прошло» слишком грубо: две стратегии
    могут обе пройти проверку, но одна работает ровно, а вторая еле-еле. Счёт
    по каждому хосту в отдельности эту разницу видит.
    """
    targets = probe_targets(group_ids)
    # Живые имена, замеченные в трафике. Именно они решают, будет ли грузиться
    # видео: постоянные проверочные хосты до раздающих серверов не достают.
    for gid, hosts in (extra or {}).items():
        if gid in group_ids:
            targets += [(gid, h) for h in hosts]
    if not targets:
        return {}
    jobs = [(gid, host) for gid, host in targets for _ in range(max(1, rounds))]
    out: Dict[str, list] = {gid: [0, 0] for gid, _ in targets}
    workers = max(1, min(MAX_WORKERS, len(jobs)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [(gid, ex.submit(test_host, host, timeout)) for gid, host in jobs]
        for gid, fut in futs:
            try:
                ok = fut.result()
            except Exception:
                ok = False
            out[gid][1] += 1
            if ok:
                out[gid][0] += 1
    return {gid: (v[0], v[1]) for gid, v in out.items()}


def internet_alive(timeout: float = 4.0) -> bool:
    """Работает ли сеть вообще (контрольный незаблокированный хост)."""
    return test_host(CONTROL_HOST, timeout)


def summary_groups(ok: Dict[str, bool]) -> str:
    good = sum(1 for v in ok.values() if v)
    return f"{good}/{len(ok)} групп доступно"


def profile_to_candidate(body: Dict, label: str) -> Optional[Dict]:
    """Обратное превращение: сохранённый профиль -> комбинация для перебора.

    Нужно, чтобы подбор начинал с того, что уже работало у этого человека.
    Сеть у него та же и провайдер тот же — прошлый ответ верен куда чаще, чем
    любой кандидат из общего списка, а стоит проверка одну итерацию.
    """
    if not isinstance(body, dict) or not body.get("strategy"):
        return None
    out = {
        "label": label,
        "strategy": body["strategy"],
        "split": body.get("split_mode", "pos2"),
        "fooling": body.get("fooling", "badseq"),
        "ttl": int(body.get("fake_ttl", 4)),
        "fakes": int(body.get("fake_count", 1)),
        "segs": int(body.get("seg_count", 3)),
        "ovl": int(body.get("seqovl", 0)),
        "id0": bool(body.get("ip_id_zero", False)),
    }
    sni = body.get("fake_sni")
    if sni and sni != DEFAULT_FAKE_SNI:
        out["sni"] = sni
    return out


def _shape(c: Dict) -> tuple:
    """Что делает кандидат, без учёта подписи. Для отсева повторов."""
    return (c["strategy"], c.get("split", "pos2"), c.get("fooling", "badseq"),
            int(c.get("ttl", 4)), int(c.get("fakes", 1)), int(c.get("segs", 3)),
            int(c.get("ovl", 0)), bool(c.get("id0", False)),
            c.get("sni") or DEFAULT_FAKE_SNI)


def all_candidates(head: Optional[List[Dict]] = None) -> List[Dict]:
    """Полный план подбора: сперва проверенные комбинации, затем сетка.

    `head` — то, что уже работало раньше; идёт первым и из остального списка
    вычёркивается, чтобы не гонять одно и то же дважды.
    """
    out: List[Dict] = []
    seen = set()
    for c in list(head or []) + list(CANDIDATES) + grid_candidates():
        key = _shape(c)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


# Одна проверка = поднять движок, прогнать рукопожатия, погасить движок.
# Считано на живой сети: рукопожатие к открытому хосту укладывается в 1.3 с,
# к закрытому — всегда упирается в таймаут, быстрых отказов провайдер не даёт.
SECONDS_PER_CANDIDATE = 4


def eta_seconds(pending: int, done: int, total: Optional[int] = None) -> int:
    """Грубая оценка остатка."""
    left = max(0, (len(all_candidates()) if total is None else total) - done)
    return int(left * SECONDS_PER_CANDIDATE) if pending else 0


# --- совместимость со старым кодом ----------------------------------------
TEST_TARGETS: List[Tuple[str, str]] = [
    (services.title(gid), host) for gid, host in probe_targets(services.GROUP_IDS)
]


def test_all(targets, timeout: float = 4.0) -> Dict[str, bool]:
    """Параллельно проверить список (имя, хост). Возвращает {имя: успех}."""
    results: Dict[str, bool] = {}
    if not targets:
        return results
    workers = max(1, min(MAX_WORKERS, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {name: ex.submit(test_host, host, timeout) for name, host in targets}
        for name, fut in futs.items():
            try:
                results[name] = fut.result()
            except Exception:
                results[name] = False
    return results


def summary(ok: Dict[str, bool]) -> str:
    good = sum(1 for v in ok.values() if v)
    return f"{good}/{len(ok)} сервисов доступно"
