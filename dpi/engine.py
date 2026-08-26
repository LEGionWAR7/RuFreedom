"""
Движок обхода DPI (TCP + QUIC/UDP), с отдельной стратегией на каждую группу
сервисов.

Как это работает. WinDivert отдаёт нам только те исходящие пакеты, которые
могут нести имя сайта: TLS-рукопожатие, начало HTTP-запроса и QUIC Initial.
В них находится имя хоста, по имени определяется группа (Discord, YouTube,
Epic…), а у группы — свой профиль обхода. Дальше пакет пересобирается так,
чтобы DPI не смог прочитать имя, а сервер получил всё как обычно.

Отбор пакетов делает драйвер, а не Python: раньше фильтр забирал ВЕСЬ
исходящий трафик на портах 80/443 и каждый пакет проходил через Python.
На живой скорости очередь драйвера переполнялась, пакеты терялись — и
интернет с включённым обходом работал хуже, чем без него.

TCP-техники (strategy):
  * split        — разрезать на 2 сегмента и отправить по порядку;
  * disorder     — то же, но сегменты уходят в обратном порядке;
  * fake         — перед реальными данными «фальшивый» ClientHello (см. fooling);
  * fakedisorder — fake + обратный порядок сегментов;
  * multisplit   — разрезать на несколько сегментов (seg_count);
  * multidisorder— то же в обратном порядке.

Способ «обмана» фальшивого сегмента (fooling): ttl | badsum | badseq |
ttlbadsum | none — см. комментарии в dpi/config.py.

QUIC-режимы (quic_mode):
  * drop     — гасить QUIC Initial → откат на TCP/TLS (там работает desync);
  * fake     — перед реальным Initial слать фальшивый с низким TTL;
  * ipfrag   — разбить QUIC Initial на два IP-фрагмента;
  * off      — не трогать QUIC.
"""

from __future__ import annotations

import os
import struct
import threading
import time
from collections import OrderedDict
from typing import Callable, Dict, List, Optional, Tuple

from . import fakes, protocols
from .config import Profile
from .hostlist import HostList

try:
    import pydivert
except ImportError:  # pragma: no cover
    pydivert = None


# сколько адресов помним для сопоставления QUIC-трафика с группой
_IP_CACHE_MAX = 4096
# сколько UDP-потоков отслеживаем для голосового обхода
_UDP_FLOW_MAX = 2048
# первые N пакетов UDP-потока получают подделку, дальше поток не трогаем
# Сколько первых пакетов потока прикрываем подделкой. У zapret это
# `--dpi-desync-cutoff=n2`: DPI решает судьбу потока по самому его началу,
# дальше смотреть уже нечего, и трогать поток незачем.
_UDP_FLOW_CUTOFF = 2

# Размер голосовой подделки. У zapret это готовый QUIC Initial к
# www.google.com размером около 1200 байт — столько же занимает настоящий
# QUIC Initial, и DPI видит ровно то, что привык видеть.
_VOICE_FAKE_SIZE = 1200


class Engine:
    def __init__(self, config, logger: Optional[Callable[[str], None]] = None) -> None:
        self.cfg = config
        self.hostlist = HostList()
        # Имена, которые реально прошли через нас. Подбор проверяется на
        # заранее заданных хостах, а видео YouTube раздают серверы с именами
        # вида rr5---sn-q4fl6nzy.googlevideo.com — их не угадать, но их
        # можно запомнить и потом мерить именно на них.
        self.seen_hosts: Dict[str, "OrderedDict"] = {}
        self._log = logger or print
        self._w = None
        self._running = False
        self._lock = threading.Lock()
        # run() можно вызвать ровно один раз: экземпляр одноразовый. Иначе два
        # потока перезаписывали бы друг другу дескриптор WinDivert молча.
        self._started = False
        # взводится, когда драйвер открыт ИЛИ запуск провалился — чтобы тот,
        # кто ждёт готовности, не завис на упавшем старте
        self.ready = threading.Event()
        self.error: Optional[str] = None
        # адрес сервера -> группа. QUIC не отдаёт имя хоста, но к моменту, когда
        # браузер идёт по QUIC, он почти всегда уже сходил на тот же адрес по
        # TCP — оттуда группа и берётся.
        self._ip_group: "OrderedDict[str, str]" = OrderedDict()
        # (адрес, порт) -> сколько пакетов потока уже видели
        self._udp_flows: "OrderedDict[Tuple[str, int], int]" = OrderedDict()
        self._last_log: Dict[str, float] = {}
        # (порт_от, порт_до, группа) — считается один раз при старте, чтобы не
        # пересобирать список на каждый UDP-пакет
        self._udp_spans: List[Tuple[int, int, str]] = []
        self._quic_fallback: Optional[Profile] = None
        # статистика за запуск
        self.stats = {"packets": 0, "bytes": 0, "tcp": 0, "quic": 0,
                      "started": None}

    @property
    def running(self) -> bool:
        return self._running

    # -- запуск / остановка ------------------------------------------------
    def run(self) -> None:
        with self._lock:
            if self._started:
                raise RuntimeError("Engine.run() уже вызван для этого экземпляра")
            self._started = True
        try:
            self._run()
        except Exception as exc:
            self.error = str(exc)
            raise
        finally:
            # что бы ни случилось — снимаем с ожидающих блокировку
            self.ready.set()

    def _run(self) -> None:
        if pydivert is None:
            raise RuntimeError(
                "Не установлен pydivert. Выполни: pip install -r requirements.txt"
            )

        # источник списка хостов: карта «домен -> группа», просто набор, либо файл
        if getattr(self.cfg, "host_groups", None):
            self.hostlist.add_map(self.cfg.host_groups)
        elif self.cfg.hosts:
            self.hostlist.add_many(self.cfg.hosts)
        else:
            self.hostlist.load(self.cfg.hostlist_path)

        self.hostlist.exclude_many(getattr(self.cfg, "exclude", None) or ())

        if self.hostlist.empty:
            self._log("[*] Список хостов пуст — обход применяется ко ВСЕМУ трафику.")
        else:
            self._log(f"[*] Активных доменов: {self.hostlist.size}")
        if self.hostlist.excluded:
            self._log(f"[*] Не трогаем: {self.hostlist.excluded} доменов "
                      f"(банки, госуслуги и то, что и так открывается).")

        for gid, prof in sorted(getattr(self.cfg, "profiles", {}).items()):
            self._log(f"[*] {gid}: {prof.label()} | QUIC: {prof.quic_mode}")
        if not getattr(self.cfg, "profiles", None):
            self._log(f"[*] Стратегия: {self.cfg.default_profile().label()}")

        self._udp_spans = self._collect_udp_spans()
        self._quic_fallback = self._strictest_quic()
        if self._quic_fallback.quic_mode == "drop":
            self._log("[*] QUIC гасится — браузер перейдёт на TCP/TLS, где обход "
                      "знает имя сайта. Если что-то стало медленнее, поставь QUIC: off.")
        if self._udp_spans:
            self._log("[*] Обход голосового UDP включён: "
                      + ", ".join(f"{g} {lo}-{hi}" for lo, hi, g in self._udp_spans))

        filt = self._build_filter()
        self._log(f"[*] WinDivert: {filt}")

        # Драйвер открываем и закрываем вручную, без `with`.
        #
        # Остановка приходит из ДРУГОГО потока: stop() закрывает дескриптор,
        # чтобы прервать recv(), который иначе ждал бы пакет вечно. Если после
        # этого закрытием займётся ещё и `with`, второй раз закрывать уже
        # нечего — и наружу летело «WinError 6: неверный дескриптор».
        w = pydivert.WinDivert(filt)
        w.open()
        try:
            self._w = w
            self._running = True
            self.stats["started"] = time.time()
            self.ready.set()          # драйвер открыт — можно считать запущенным
            self._log("[*] Обход запущен.")
            while self._running:
                try:
                    packet = w.recv()
                except Exception as exc:  # handle закрыт из stop() либо ошибка
                    if self._running:
                        self._log(f"[!] Ошибка приёма пакета: {exc}")
                    break
                try:
                    self._handle(packet)
                except Exception as exc:
                    self._log(f"[!] Ошибка обработки: {exc}")
                    try:
                        w.send(packet)
                    except Exception:
                        pass
        finally:
            self._running = False
            self._w = None
            # закрываем только если stop() этого ещё не сделал
            try:
                if w.is_open:
                    w.close()
            except Exception:
                pass
        self._log("[*] Обход остановлен.")

    def stop(self) -> None:
        with self._lock:
            self._running = False
            if self._w is not None:
                try:
                    self._w.close()
                except Exception:
                    pass

    # -- фильтр WinDivert --------------------------------------------------
    def _build_filter(self) -> str:
        """Условие отбора пакетов. Считает ЯДРО, а не Python.

        Забираем только то, где может лежать имя сайта:
          * TLS-запись рукопожатия (первые два байта 16 03) на TLS-портах;
          * начало HTTP-запроса на 80-м (первый байт — заглавная латиница);
          * QUIC-пакет с длинным заголовком типа Initial (первый байт C0..CF);
          * весь UDP в диапазоне голосовых портов, если он включён.
        Всё остальное ядро пропускает мимо нас на полной скорости.
        """
        tcp_parts = []
        for port in self.cfg.ports:
            if int(port) == 80:
                tcp_parts.append("(tcp.DstPort == 80 and "
                                 "tcp.Payload[0] >= 0x41 and tcp.Payload[0] <= 0x5A)")
            else:
                tcp_parts.append(f"(tcp.DstPort == {int(port)} and "
                                 f"tcp.Payload16[0] == 0x1603)")
        tcp = ("(tcp and tcp.PayloadLength > 0 and ("
               + " or ".join(tcp_parts) + "))")

        udp_parts = []
        if any(p.quic_mode != "off" for p in self._profiles()):
            udp_parts.append("(udp.DstPort == 443 and "
                             "udp.Payload[0] >= 0xC0 and udp.Payload[0] <= 0xCF)")
        for lo, hi, _gid in self._udp_spans:
            udp_parts.append(f"(udp.DstPort >= {lo} and udp.DstPort <= {hi})")

        if not udp_parts:
            return f"outbound and (ip or ipv6) and {tcp}"
        udp = ("(udp and udp.PayloadLength > 0 and ("
               + " or ".join(udp_parts) + "))")
        return f"outbound and (ip or ipv6) and ({tcp} or {udp})"

    def _profiles(self) -> List[Profile]:
        get = getattr(self.cfg, "active_profiles", None)
        return get() if get else [self.cfg.default_profile()]

    def _collect_udp_spans(self) -> List[Tuple[int, int, str]]:
        """Диапазоны не-QUIC UDP, которые нас интересуют (голос Discord)."""
        out = []
        ranges = getattr(self.cfg, "udp_ranges", None) or {}
        profiles = getattr(self.cfg, "profiles", None) or {}
        for gid, spans in ranges.items():
            if not spans:
                continue
            prof = profiles.get(gid)
            # Профиля у группы может не быть вовсе, и это НОРМАЛЬНО: TCP-обход
            # Discord не нужен (discord.com открывается сам), а голос прикрыть
            # надо. Раз диапазон сюда положили — значит человек включил
            # карточку и не выключал голосовой обход; больше спрашивать не у
            # кого. Профиль спрашиваем, только если он есть.
            if prof is not None and not prof.udp_fake:
                continue
            # у группы может быть несколько диапазонов (у Discord их два)
            if spans and isinstance(spans[0], (list, tuple)):
                for lo, hi in spans:
                    out.append((int(lo), int(hi), gid))
            else:
                out.append((int(spans[0]), int(spans[1]), gid))
        return out

    def _strictest_quic(self) -> Profile:
        """Профиль для QUIC, чью группу мы ещё не знаем.

        Имени сайта в QUIC нет: SNI лежит внутри зашифрованного CRYPTO-кадра.
        Группу мы узнаём только по адресу, а его запоминаем с TCP-пути — но на
        холодном старте браузер часто пробует QUIC ДО первого TCP-соединения.
        Тогда работает профиль по умолчанию (тот, что в настройках сверху), а
        не самый строгий из групповых: иначе «QUIC: off» в настройках не
        выключал бы QUIC, пока хоть у одной группы стоит drop.

        Режим drop безопасен: он лишь роняет соединение на TCP/TLS, где обход
        работает с полным знанием имени. Цена — один лишний круг на первое
        соединение к сайтам, которых нет в списке.
        """
        return self.cfg.default_profile()

    # -- маршрутизация пакета ----------------------------------------------
    def _handle(self, pkt) -> None:
        self.stats["packets"] += 1
        self.stats["bytes"] += len(pkt.payload or b"")
        if pkt.udp is not None:
            self._handle_udp(pkt)
        else:
            self._handle_tcp(pkt)

    def _note(self, key: str, text: str, every: float = 5.0) -> None:
        """Не засорять журнал: одна и та же строка не чаще раза в `every` секунд."""
        now = time.monotonic()
        if now - self._last_log.get(key, 0.0) < every:
            return
        self._last_log[key] = now
        if len(self._last_log) > 512:
            self._last_log.clear()
        self._log(text)

    def _remember_host(self, host: str, group: str) -> None:
        """Запомнить живое имя сервера группы (не больше 8 на группу)."""
        if not host or not group:
            return
        box = self.seen_hosts.setdefault(group, OrderedDict())
        if host in box:
            box.move_to_end(host)
            return
        box[host] = True
        while len(box) > 8:
            box.popitem(last=False)

    def _remember_ip(self, addr: Optional[str], group: str) -> None:
        if not addr or not group:
            return
        cache = self._ip_group
        cache[addr] = group
        cache.move_to_end(addr)
        while len(cache) > _IP_CACHE_MAX:
            cache.popitem(last=False)

    # -- TCP ---------------------------------------------------------------
    def _handle_tcp(self, pkt) -> None:
        payload = pkt.payload or b""
        target = protocols.find_sni(payload) or protocols.find_http_host(payload)
        if target is None:
            self._w.send(pkt)
            return

        start, end, host = target
        group = self.hostlist.resolve(host)
        if group is None:          # хост не наш — не трогаем
            self._w.send(pkt)
            return

        prof = self.cfg.profile_for(group)
        self._remember_ip(pkt.dst_addr, group)
        self._remember_host(host, group)

        positions = self._positions(start, end, len(payload), prof, host)
        if not positions:
            self._w.send(pkt)
            return

        self.stats["tcp"] += 1
        tag = f"[{group}] " if group else ""
        self._note(f"tcp:{host}:{prof.label()}",
                   f"[+] TCP {host} {tag}-> {prof.label()} split@{positions}")
        self._desync_tcp(pkt, payload, positions, prof)

    @staticmethod
    def _sld_span(host: str, start: int, end: int) -> Tuple[int, int]:
        """Границы домена второго уровня внутри payload.

        Для www.youtube.com это «youtube», для youtubei.googleapis.com —
        «googleapis». Именно по этой метке zapret режет по умолчанию: имя
        сайта разваливается там, где DPI ищет его целиком, а не в начале.
        """
        labels = [l for l in host.split(".") if l]
        if len(labels) < 2:
            return start, end
        sld = labels[-2]
        off = host.rfind("." + sld + "." + labels[-1])
        lo = start + (off + 1 if off >= 0 else 0)
        hi = min(lo + len(sld), end)
        if not (start <= lo < hi <= end):
            return start, end
        return lo, hi

    def _positions(self, start: int, end: int, length: int,
                   prof: Profile, host: str = "") -> List[int]:
        """Точки разреза payload."""
        mode = prof.split_mode
        if mode.startswith("pos"):
            # абсолютное смещение от начала пакета — режет заголовок TLS-записи
            try:
                base = int(mode[3:])
            except ValueError:
                base = 2
        elif mode.startswith("host+"):
            # на N байт правее начала имени: разница в один байт решает, какой
            # хост берётся, а какой нет — проверено на youtubei.googleapis.com
            try:
                base = start + int(mode[5:])
            except ValueError:
                base = start + 1
        elif mode == "host-start":
            base = start
        elif mode == "host-end":
            base = end
        elif mode == "mid-host":
            base = start + max(1, (end - start) // 2)
        elif mode in ("sld", "midsld", "endsld"):
            lo, hi = self._sld_span(host, start, end)
            base = {"sld": lo, "midsld": (lo + hi) // 2, "endsld": hi}[mode]
        else:  # first-char
            base = start + 1

        base = max(1, min(base, length - 1))
        want = prof.segments
        if want <= 2:
            return [base]

        # multi: остальные точки раскладываем до конца имени хоста — так DPI
        # приходится собирать имя из нескольких кусков, а не из двух
        hi = min(max(end, base + 2), length - 1)
        cuts = [base]
        if hi > base:
            step = max(1, (hi - base) // (want - 1))
            p = base
            while len(cuts) < want - 1:
                p += step
                if p >= length - 1:
                    break
                cuts.append(p)
        return sorted({c for c in cuts if 0 < c < length})

    def _desync_tcp(self, pkt, payload: bytes, positions: List[int],
                    prof: Profile) -> None:
        header_len = len(pkt.raw) - len(payload)
        header = bytes(pkt.raw[:header_len])
        base_seq = pkt.tcp.seq_num

        bounds = [0] + positions + [len(payload)]
        segments = []
        for i in range(len(bounds) - 1):
            a, b = bounds[i], bounds[i + 1]
            segments.append((base_seq + a, payload[a:b]))

        # Перекрытие номеров: первый кусок уходит с номером на N назад, а
        # впереди него — целый ClientHello на чужое имя. Сервер по правилам TCP
        # отбрасывает всё, что лежит раньше начала потока, и получает свои
        # данные целыми. DPI же складывает поток подряд, видит в начале
        # разбираемый ClientHello на разрешённый сайт и пропускает соединение.
        if prof.seqovl and len(segments) >= 2:
            n = prof.seqovl
            seq0, chunk0 = segments[0]
            segments[0] = ((seq0 - n) & 0xFFFFFFFF,
                           self._overlap_bytes(n, prof, payload) + chunk0)

        if prof.uses_fake and not prof.fake_between:
            for i in range(prof.fake_count):
                # каждая подделка собирается заново: у неё свой random внутри
                # ClientHello, иначе повторы уходили бы байт-в-байт одинаковыми
                # и выдавали бы себя одним этим
                self._send_fake(pkt, header, base_seq,
                                self._fake_payload(payload, prof), prof, i)

        # подделка между кусками: её номер совпадает со вторым куском, поэтому
        # у DPI на месте второго куска оказывается мусор
        mid_seq = segments[1][0] if (prof.fake_between and len(segments) >= 2) else None

        ordered = list(reversed(segments)) if prof.reorders else segments
        for seq, chunk in ordered:
            if mid_seq is not None and seq == mid_seq:
                for i in range(prof.fake_count):
                    self._send_fake(pkt, header, mid_seq,
                                    self._fake_payload(payload, prof, len(chunk)),
                                    prof, i)
            self._w.send(self._build(pkt, header, chunk, seq=seq,
                                     ip_id_zero=prof.ip_id_zero))

    def _overlap_bytes(self, n: int, prof: Profile,
                       payload: bytes = b"") -> bytes:
        """Чем заполнить перекрытие: разбираемым ClientHello на чужое имя.

        Мусор здесь почти бесполезен — DPI просто не опознает начало потока и
        может дождаться настоящего имени дальше. А вот целый ClientHello он
        разбирает и принимает решение по нему. Если запрошено меньше, чем
        занимает минимальный ClientHello, повторяем его по кругу — заголовок
        TLS-записи в начале всё равно оказывается на месте.
        """
        if n >= 260:
            body = fakes.tls_fake(prof.fake_sni, n, fakes.real_session_id(payload))
            if len(body) == n:
                return body
        base = fakes.tls_fake(prof.fake_sni)
        return (base * (n // len(base) + 1))[:n]

    def _fake_payload(self, payload: bytes, prof: Profile,
                      size: Optional[int] = None) -> bytes:
        """Содержимое подделки.

        Это должен быть РАЗБИРАЕМЫЙ ClientHello с чужим именем сайта: DPI
        обязан прочитать из него имя и успокоиться. Длину берём как у
        настоящего пакета, чтобы подделка не выделялась размером.

        `size` задаётся для подделки МЕЖДУ кусками: там она занимает место
        второго куска, и её задача — не назваться чужим именем, а сломать
        пересборку. Если места на настоящий ClientHello не хватает, кладём
        случайные байты: сервер эту подделку всё равно выбросит.
        """
        # dupsid: тот же session_id, что у настоящего пакета. DPI, который
        # следит за session_id, считает подделку тем же рукопожатием и
        # запоминает имя из неё; с разным id он видит два разных и не ведётся.
        sid = fakes.real_session_id(payload)
        if size is not None:
            body = fakes.tls_fake(prof.fake_sni, size, sid)
            return body if len(body) == size else os.urandom(max(1, size))
        if protocols.is_tls_client_hello(payload):
            return fakes.tls_fake(prof.fake_sni, len(payload), sid)
        if protocols.is_http_request(payload):
            return fakes.http_fake(prof.fake_sni)
        return payload

    def _send_fake(self, src, header: bytes, seq: int, fake_payload: bytes,
                   prof: Profile, index: int) -> None:
        """Фальшивый сегмент: DPI его учитывает, сервер — нет."""
        fooling = prof.fooling
        is_v4 = len(header) > 0 and (header[0] >> 4) == 4
        # для IPv6 ручная порча контрольной суммы не проверена — там смещения
        # другие, поэтому честно откатываемся на badseq (он от версии IP не зависит)
        if not is_v4 and fooling in ("badsum", "ttlbadsum"):
            fooling = "badseq"

        seq_use = seq
        if fooling == "badseq":
            # номер отмотан далеко назад: сервер сочтёт сегмент устаревшим и
            # выбросит, а DPI его засчитает. Смещение разное у каждой подделки,
            # иначе повторы были бы байт-в-байт одинаковыми.
            seq_use = (seq - 0x40000 - index * 0x10000) & 0xFFFFFFFF

        ttl = prof.fake_ttl if fooling in ("ttl", "ttlbadsum") else None

        if fooling in ("badsum", "ttlbadsum"):
            raw = bytearray(header) + bytearray(fake_payload)
            ihl = (raw[0] & 0x0F) * 4
            struct.pack_into("!I", raw, ihl + 4, seq_use & 0xFFFFFFFF)  # TCP seq
            raw[2:4] = len(raw).to_bytes(2, "big")                      # IP total len
            if ttl is not None:
                raw[8] = ttl & 0xFF
            raw[10:12] = b"\x00\x00"
            raw[10:12] = self._ip_checksum(bytes(raw[:ihl])).to_bytes(2, "big")
            raw[ihl + 16:ihl + 18] = b"\xba\xdd"                        # неверная сумма
            p = pydivert.Packet(bytes(raw), src.interface, src.direction)
            self._w.send(p, recalculate_checksum=False)
            return

        self._w.send(self._build(src, header, fake_payload, seq=seq_use, ttl=ttl))

    # -- UDP / QUIC --------------------------------------------------------
    def _handle_udp(self, pkt) -> None:
        payload = pkt.payload or b""
        dport = pkt.dst_port or 0

        if dport == 443 and protocols.is_quic_initial(payload):
            self._handle_quic(pkt, payload)
            return

        # Не-QUIC UDP: голос и демонстрация экрана Discord.
        #
        # Решаем по порту — диапазон узкий, и попасть в него чужому почти
        # нечем. Требовать вдобавок знакомый АДРЕС (как делала 1.2.0) нельзя:
        # адреса мы узнаём с TCP-пути, а он для Discord часто выключен —
        # discord.com открывается сам, и группа уходит в «не трогаю». Тогда
        # адрес не узнать никогда, и голос оставался без обхода.
        #
        # Адрес всё же смотрим, но только чтобы ОТКАЗАТЬСЯ: если сервер
        # заведомо принадлежит другой группе, пакет не наш.
        known = self._ip_group.get(pkt.dst_addr or "")
        for lo, hi, gid in self._udp_spans:
            if not (lo <= dport <= hi):
                continue
            if known is not None and known != gid:
                break                      # это чужой сервер, не наш
            self._handle_voice(pkt, payload, gid)
            return

        self._w.send(pkt)

    def _handle_quic(self, pkt, payload: bytes) -> None:
        group = self._ip_group.get(pkt.dst_addr or "")
        prof = (self.cfg.profile_for(group) if group
                else (self._quic_fallback or self._strictest_quic()))
        mode = prof.quic_mode
        if mode == "off":
            self._w.send(pkt)
            return

        self.stats["quic"] += 1
        tag = f"[{group}] " if group else ""
        if mode == "drop":
            self._note(f"quic:{group}:drop",
                       f"[+] QUIC Initial {tag}-> drop (откат на TCP/TLS)")
            return  # не пересылаем -> приложение откатится на TCP
        if mode == "fake":
            self._note(f"quic:{group}:fake",
                       f"[+] QUIC Initial {tag}-> fake (низкий TTL)")
            header_len = len(pkt.raw) - len(payload)
            header = bytes(pkt.raw[:header_len])
            for _ in range(max(1, prof.fake_count)):
                self._w.send(self._build(pkt, header, fakes.quic_fake(len(payload)),
                                         ttl=prof.fake_ttl))
            self._w.send(pkt)
            return
        if mode == "ipfrag":
            if self._send_ip_fragments(pkt):
                self._note(f"quic:{group}:ipfrag",
                           f"[+] QUIC Initial {tag}-> ipfrag (2 IP-фрагмента)")
            else:
                self._w.send(pkt)
            return
        self._w.send(pkt)

    def _handle_voice(self, pkt, payload: bytes, group: str) -> None:
        """Обход для голосового UDP (Discord).

        Здесь повторена конфигурация zapret, которой люди пользуются годами:
        подделка на первых двух пакетах потока, шесть повторов, содержимое —
        полноразмерный QUIC Initial. Своё было в каждой из трёх мелочей, и
        каждая по отдельности ломала весь приём.

        ПОЧЕМУ НЕ ЗАЖИМАЕМ TTL. В 1.3.0 стоял потолок в два хопа: логика была
        та, что подделка не должна доехать до сервера Discord. Логика неверна.
        Оборудование, которое режет голос, стоит не обязательно на втором
        хопе — у разных провайдеров оно на разном расстоянии, и с потолком в
        два хопа подделку просто никто не видел. Приём переставал работать
        целиком, а выглядело это как «обход не помогает».

        Ронять TTL и не требуется. Подделка — синтаксически верный QUIC, а
        голосовой сервер Discord ждёт RTP. Даже доехав, она разбору не
        поддаётся и отбрасывается на первом же байте: у RTP старшие два бита
        первого байта равны 10, у длинного заголовка QUIC — 11. Спутать их
        нельзя. Поэтому по умолчанию TTL не трогаем вовсе (voice_ttl = 0), а
        кому нужно — тот выставит своё число в настройках.
        """
        key = (pkt.dst_addr or "", pkt.dst_port or 0)
        seen = self._udp_flows.get(key, 0)
        if seen >= _UDP_FLOW_CUTOFF:
            self._w.send(pkt)
            return

        self._udp_flows[key] = seen + 1
        self._udp_flows.move_to_end(key)
        while len(self._udp_flows) > _UDP_FLOW_MAX:
            self._udp_flows.popitem(last=False)

        prof = self.cfg.profile_for(group)
        header_len = len(pkt.raw) - len(payload)
        header = bytes(pkt.raw[:header_len])
        ttl = prof.voice_ttl if prof.voice_ttl > 0 else None
        repeats = max(1, min(16, prof.voice_repeats))
        self.stats["quic"] += 1
        self._note("voice", f"[+] UDP {key[1]} [{group}] -> подделка перед голосом "
                            f"(x{repeats}"
                            + (f", ttl {ttl}" if ttl else ", свой TTL") + ")")
        for _ in range(repeats):
            try:
                self._w.send(self._build(pkt, header,
                                         fakes.quic_fake(_VOICE_FAKE_SIZE),
                                         ttl=ttl))
            except Exception:
                break
        self._w.send(pkt)

    # -- IP-фрагментация (для QUIC) ----------------------------------------
    def _send_ip_fragments(self, pkt) -> bool:
        """Разбить IPv4-пакет на два фрагмента. True, если получилось."""
        raw = bytes(pkt.raw)
        if not raw or (raw[0] >> 4) != 4:
            return False  # фрагментируем только IPv4
        ihl = (raw[0] & 0x0F) * 4
        ip_payload = raw[ihl:]
        L = len(ip_payload)
        if L <= 16:
            return False

        # точка разреза кратна 8 байтам, ближе к середине
        cut = (L // 2) & ~0x7
        if cut < 8:
            cut = 8
        if cut >= L:
            cut = (L - 8) & ~0x7
        if cut < 8:
            return False

        header = bytearray(raw[:ihl])

        frag1 = self._make_ip_fragment(header, ip_payload[:cut], offset=0, mf=True)
        frag2 = self._make_ip_fragment(header, ip_payload[cut:], offset=cut // 8,
                                       mf=False)
        # чексумму UDP не трогаем (она верна для всей датаграммы), поэтому
        # отправляем без пересчёта контрольных сумм WinDivert'ом.
        self._send_raw(pkt, frag1)
        self._send_raw(pkt, frag2)
        return True

    def _make_ip_fragment(self, header: bytearray, chunk: bytes,
                          offset: int, mf: bool) -> bytes:
        h = bytearray(header)
        total = len(h) + len(chunk)
        h[2:4] = total.to_bytes(2, "big")          # Total Length
        flags_off = (offset & 0x1FFF) | (0x2000 if mf else 0)  # MF-бит + offset
        h[6:8] = flags_off.to_bytes(2, "big")
        h[10:12] = b"\x00\x00"                      # обнулить чексумму
        h[10:12] = self._ip_checksum(h).to_bytes(2, "big")
        return bytes(h) + bytes(chunk)

    @staticmethod
    def _ip_checksum(header: bytes) -> int:
        s = 0
        for i in range(0, len(header), 2):
            word = (header[i] << 8) + (header[i + 1] if i + 1 < len(header) else 0)
            s += word
            s = (s & 0xFFFF) + (s >> 16)
        return (~s) & 0xFFFF

    def _send_raw(self, src, raw: bytes) -> None:
        p = pydivert.Packet(raw, src.interface, src.direction)
        self._w.send(p, recalculate_checksum=False)

    # -- сборка пакетов ----------------------------------------------------
    def _build(self, src, header: bytes, chunk: bytes,
               seq: Optional[int] = None, ttl: Optional[int] = None,
               ip_id_zero: bool = False):
        raw = bytearray(header) + bytearray(chunk)
        p = pydivert.Packet(bytes(raw), src.interface, src.direction)
        if p.ipv4 is not None:
            # для IPv4 raw == весь IP-пакет, поэтому total length = len(raw)
            p.ipv4.packet_len = len(raw)
            if ttl is not None:
                p.ipv4.ttl = ttl
            if ip_id_zero:
                p.ipv4.ident = 0
        elif p.ipv6 is not None:
            p.ipv6.packet_len = len(raw)
            if ttl is not None:
                p.ipv6.hop_limit = ttl
        if p.udp is not None:
            # У UDP своё поле длины, и его тоже надо чинить. TCP этим не
            # страдает — там длины в заголовке нет вовсе, поэтому раньше
            # проблема не всплывала: единственная UDP-подделка (QUIC) по
            # случайности выходила ровно того же размера, что и оригинал.
            # Голосовая подделка такого совпадения не даёт, и датаграмма с
            # неверной длиной — это уже битый пакет.
            p.udp.payload_len = len(chunk)
        if seq is not None and p.tcp is not None:
            p.tcp.seq_num = seq
        return p
