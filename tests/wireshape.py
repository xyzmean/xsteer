#!/usr/bin/env python3
"""Форма трафика на проводе: чем xsteer отличается от настоящего TLS-транспорта.

ЗАЧЕМ ЭТОТ ИНСТРУМЕНТ. Утверждение «выглядит как TLS» проверяется не намерением автора, а
измерением: берём запись нашего трафика и запись трафика настоящего xhttp (Xray, тот же TLS, тот
же путь, та же нагрузка) и считаем по ним ОДНИ И ТЕ ЖЕ признаки. Всё, где числа расходятся, —
это то, по чему нас можно отличить, и дальше уже решение: чинить, платить или признать.

Признаки выбраны не наугад, а по тому, что видит наблюдатель на проводе и что дёшево считать в
реальном времени: опции в SYN, поведение окна, повторные передачи, границы записей TLS
относительно границ сегментов, распределение размеров, периодичность и способ завершения.

    python3 tests/wireshape.py запись.pcap [ещё.pcap ...]
    python3 tests/wireshape.py --port 443 xsteer.pcap --port 8443 xhttp.pcap
"""

import collections
import struct
import sys


def read_pcap(path):
    """Пакеты из pcap: (время, кадр). Своя разборка, потому что зависимость ради двадцати строк —
    это зависимость, которую придётся ставить на каждой машине, где стенд захотят прогнать."""
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack("<I", gh[:4])[0]
        if magic == 0xA1B2C3D4:
            endian, nano = "<", False
        elif magic == 0xD4C3B2A1:
            endian, nano = ">", False
        elif magic == 0xA1B23C4D:
            endian, nano = "<", True
        elif magic == 0x4D3CB2A1:
            endian, nano = ">", True
        else:
            raise SystemExit("%s: не pcap (magic %08x)" % (path, magic))
        link = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            ph = f.read(16)
            if len(ph) < 16:
                return
            ts_s, ts_f, caplen, _ = struct.unpack(endian + "IIII", ph)
            data = f.read(caplen)
            if len(data) < caplen:
                return
            t = ts_s + ts_f / (1e9 if nano else 1e6)
            yield t, link, data


def parse(frame, link):
    """(ip_src, ip_dst, sport, dport, flags, seq, win, opts, payload) или None."""
    if link == 1:  # Ethernet
        if len(frame) < 14 or frame[12:14] != b"\x08\x00":
            return None
        ip = frame[14:]
    elif link == 101 or link == 12:  # raw IP
        ip = frame
    elif link == 113:  # Linux SLL
        if len(frame) < 16:
            return None
        ip = frame[16:]
    else:
        return None
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 6:
        return None
    ihl = (ip[0] & 0xF) * 4
    total = struct.unpack(">H", ip[2:4])[0]
    if total > len(ip):
        total = len(ip)
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        return None
    thl = (tcp[12] >> 4) * 4
    if thl < 20 or thl > len(tcp):
        return None
    sport, dport = struct.unpack(">HH", tcp[0:4])
    seq = struct.unpack(">I", tcp[4:8])[0]
    flags = tcp[13]
    win = struct.unpack(">H", tcp[14:16])[0]
    return (ip[12:16], ip[16:20], sport, dport, flags, seq, win, tcp[20:thl], tcp[thl:])


def opt_names(opts):
    """Список опций TCP по именам: именно набор и ПОРЯДОК опций в SYN составляют отпечаток стека."""
    out, i = [], 0
    names = {0: "EOL", 1: "NOP", 2: "MSS", 3: "WS", 4: "SACK_PERM", 5: "SACK", 8: "TS"}
    while i < len(opts):
        k = opts[i]
        if k == 0:
            out.append("EOL")
            break
        if k == 1:
            out.append("NOP")
            i += 1
            continue
        if i + 1 >= len(opts):
            break
        ln = opts[i + 1]
        if ln < 2 or i + ln > len(opts):
            break
        out.append(names.get(k, "opt%d" % k))
        i += ln
    return out


def records(payload):
        """Записи TLS в нагрузке сегмента: [(тип, длина, целиком_ли_влезла)]."""
        out, i = [], 0
        while i + 5 <= len(payload):
            typ = payload[i]
            if payload[i + 1] != 0x03:
                break
            ln = struct.unpack(">H", payload[i + 3:i + 5])[0]
            whole = i + 5 + ln <= len(payload)
            out.append((typ, ln, whole))
            if not whole:
                break
            i += 5 + ln
        return out


class Side:
    def __init__(self):
        self.pkts = 0
        self.bytes = 0
        self.payload_pkts = 0
        self.payload_bytes = 0
        self.acks_only = 0
        self.psh = 0
        self.wins = collections.Counter()
        self.syn_opts = None
        self.seen_seq = set()
        self.retrans = 0
        self.sizes = collections.Counter()
        self.rec_types = collections.Counter()
        self.rec_sizes = []
        self.rec_aligned = 0        # запись кончается ровно на границе сегмента
        self.rec_spanning = 0       # запись НЕ влезла в сегмент: продолжение в следующем
        self.seg_starts_rec = 0     # сегмент начинается с заголовка записи
        self.seg_no_rec = 0
        self.times = []
        self.fin = 0
        self.rst = 0
        self.first = []        # размеры первых сегментов с нагрузкой: вылеты рукопожатия
        self.small_times = []  # время малых пакетов: по ним видно keepalive


def analyse(path, port):
    sides = {}          # (кто, куда) → Side
    order = []
    for t, link, frame in read_pcap(path):
        p = parse(frame, link)
        if p is None:
            continue
        src, dst, sport, dport, flags, seq, win, opts, payload = p
        if port and port not in (sport, dport):
            continue
        key = "клиент→сервер" if dport == port else "сервер→клиент"
        s = sides.setdefault(key, Side())
        if key not in order:
            order.append(key)
        s.pkts += 1
        s.bytes += len(frame)
        s.wins[win] += 1
        s.times.append(t)
        if flags & 0x02 and not flags & 0x10:
            s.syn_opts = opt_names(opts)
        if flags & 0x02 and flags & 0x10:
            s.syn_opts = opt_names(opts)
        if flags & 0x01:
            s.fin += 1
        if flags & 0x04:
            s.rst += 1
        if flags & 0x08:
            s.psh += 1
        if not payload:
            if flags & 0x10 and not flags & 0x03:
                s.acks_only += 1
            continue
        s.payload_pkts += 1
        s.payload_bytes += len(payload)
        if len(s.first) < 6:
            s.first.append(len(payload))
        if len(payload) <= 64:
            s.small_times.append(t)
        s.sizes[len(payload)] += 1
        if seq in s.seen_seq:
            s.retrans += 1
        s.seen_seq.add(seq)
        recs = records(payload)
        if recs and payload[0] in (0x14, 0x15, 0x16, 0x17):
            s.seg_starts_rec += 1
            for typ, ln, whole in recs:
                s.rec_types[typ] += 1
                s.rec_sizes.append(ln)
                if not whole:
                    s.rec_spanning += 1
            # Ровно одна запись, кончающаяся точно на границе сегмента, — самый сильный признак
            # датаграммного транспорта: у настоящего TLS запись живёт своей длиной и границы
            # сегментов не соблюдает.
            if len(recs) >= 1 and recs[-1][2] and \
               sum(5 + ln for _, ln, _ in recs) == len(payload):
                s.rec_aligned += 1
        else:
            s.seg_no_rec += 1
    return order, sides


def show(name, order, sides):
    print("=" * 78)
    print(name)
    print("=" * 78)
    for key in order:
        s = sides[key]
        print("\n  %s" % key)
        print("    пакетов %d, из них с нагрузкой %d, только подтверждений %d"
              % (s.pkts, s.payload_pkts, s.acks_only))
        print("    нагрузки %d байт" % s.payload_bytes)
        print("    опции SYN: %s" % (", ".join(s.syn_opts) if s.syn_opts else "нет SYN в записи"))
        top = s.wins.most_common(3)
        print("    окно: разных значений %d, чаще всего %s"
              % (len(s.wins), ", ".join("%d×%d" % (v, c) for v, c in top)))
        print("    повторных передач: %d" % s.retrans)
        print("    PSH на %d%% пакетов" % (100 * s.psh // max(1, s.pkts)))
        if s.payload_pkts:
            print("    сегментов, начинающихся с заголовка записи: %d из %d (%d%%)"
                  % (s.seg_starts_rec, s.payload_pkts,
                     100 * s.seg_starts_rec // s.payload_pkts))
            print("    из них запись кончается ровно на границе сегмента: %d (%d%%)"
                  % (s.rec_aligned, 100 * s.rec_aligned // max(1, s.seg_starts_rec)))
            print("    записей, не влезших в сегмент (то есть настоящий поток): %d" % s.rec_spanning)
        if s.rec_sizes:
            rs = sorted(s.rec_sizes)
            print("    длины записей: мин %d, медиана %d, макс %d, разных %d"
                  % (rs[0], rs[len(rs) // 2], rs[-1], len(set(rs))))
            print("    типы записей: %s" % ", ".join(
                "0x%02x×%d" % (t, c) for t, c in sorted(s.rec_types.items())))
        if s.sizes:
            common = s.sizes.most_common(4)
            print("    частые размеры нагрузки: %s"
                  % ", ".join("%d×%d" % (v, c) for v, c in common))
        if s.sizes:
            mx = max(s.sizes)
            full = sum(c for v, c in s.sizes.items() if v >= mx - 8)
            print("    самый большой сегмент %d, таких (±8) %d из %d (%d%%)"
                  % (mx, full, s.payload_pkts, 100 * full // max(1, s.payload_pkts)))
        if s.first:
            print("    первые сегменты (вылеты рукопожатия): %s"
                  % ", ".join(str(v) for v in s.first))
        # Периодичность малых пакетов. Постоянный интервал — это keepalive, и он сам по себе
        # признак: у настоящего браузерного соединения таких часов нет.
        if len(s.small_times) >= 4:
            gaps = [round(b - a, 1) for a, b in zip(s.small_times, s.small_times[1:])
                    if b - a > 0.5]
            if gaps:
                mode, cnt = collections.Counter(gaps).most_common(1)[0]
                print("    малых пакетов %d; чаще всего пауза между ними %.1f с (%d раз из %d)"
                      % (len(s.small_times), mode, cnt, len(gaps)))
        print("    завершение: FIN %d, RST %d" % (s.fin, s.rst))


def main(argv):
    args, port = [], 443
    i = 0
    while i < len(argv):
        if argv[i] == "--port":
            port = int(argv[i + 1])
            i += 2
            continue
        args.append((argv[i], port))
        i += 1
    if not args:
        print(__doc__)
        return 2
    for path, p in args:
        order, sides = analyse(path, p)
        show("%s (порт %d)" % (path, p), order, sides)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
