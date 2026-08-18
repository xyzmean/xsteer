// Случаи те же, что в tests/xsroutematch.c: ошибка в маршрутизации не видна по симптому —
// «работает, но не туда», — поэтому проверяется каждое решение, а не только счастливый путь.
package route

import (
	"math/rand"
	"testing"

	"github.com/xyzmean/xsteer/conf"
)

func pfx(s string, plen int, peerNet uint32) conf.Allowed {
	var mask uint32
	if plen > 0 {
		mask = ^uint32(0) << (32 - plen)
	}
	return conf.Allowed{Net: peerNet & mask, Mask: mask, Plen: plen}
}

func TestСамыйДлинныйПрефикс(t *testing.T) {
	peers := []conf.Peer{
		{Allowed: []conf.Allowed{pfx("", 0, 0)}},                                    // пир 0: 0.0.0.0/0
		{Allowed: []conf.Allowed{pfx("", 16, 0x0A090000)}},                          // пир 1: 10.9.0.0/16
		{Allowed: []conf.Allowed{pfx("", 24, 0x0A090500), pfx("", 32, 0x08080808)}}, // пир 2
	}
	r := NewRouter(peers)
	var c Cache
	cases := []struct {
		dst  uint32
		want int
		why  string
	}{
		{0x0A090501, 2, "самое длинное совпадение /24"},
		{0x0A090101, 1, "совпадение /16, когда /24 не подошёл"},
		{0x08080808, 2, "точный адрес /32"},
		{0x01020304, 0, "умолчание 0.0.0.0/0"},
	}
	for _, cs := range cases {
		if got := r.Lookup(cs.dst, &c); got != cs.want {
			t.Errorf("%s: адрес %08x ушёл пиру %d, а не %d", cs.why, cs.dst, got, cs.want)
		}
	}

	// Кэш обязан отвечать то же, что обход. Иначе один поток трафика однажды уедет не туда, и
	// найти это можно будет только по жалобе.
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 5000; i++ {
		dst := rng.Uint32()
		want := r.Lookup(dst, nil)
		if got := r.Lookup(dst, &c); got != want {
			t.Fatalf("кэш соврал на %08x: %d вместо %d", dst, got, want)
		}
		// Тот же адрес второй раз — теперь заведомо из кэша.
		if got := r.Lookup(dst, &c); got != want {
			t.Fatalf("повторный запрос из кэша дал %d вместо %d", got, want)
		}
	}
}

func TestНетПираОтбросить(t *testing.T) {
	// Ни одного 0.0.0.0/0: пакет в чужую сеть отдавать некому.
	r := NewRouter([]conf.Peer{
		{Allowed: []conf.Allowed{pfx("", 24, 0x0A000100)}},
		{Allowed: []conf.Allowed{pfx("", 24, 0x0A000200)}},
	})
	var c Cache
	if got := r.Lookup(0x08080808, &c); got != -1 {
		t.Fatalf("пакет без адресата ушёл пиру %d — это утечка трафика между пирами", got)
	}
	// Пир → пир: ровно то, ради чего затевалась полная звезда.
	if got := r.Lookup(0x0A000205, &c); got != 1 {
		t.Errorf("пакет от пира 0 к сети пира 1 ушёл в %d", got)
	}
	// Пустая таблица тоже обязана отвечать «отбросить», а не срываться.
	if got := NewRouter(nil).Lookup(1, &c); got != -1 {
		t.Errorf("пустая таблица вернула %d", got)
	}
}

func TestПравоНаАдресИсточника(t *testing.T) {
	p := &conf.Peer{Allowed: []conf.Allowed{pfx("", 24, 0x0A000100), pfx("", 32, 0x0A4D0002)}}
	if !SrcOK(p, 0x0A000105) {
		t.Error("свой адрес из своей сети отвергнут")
	}
	if !SrcOK(p, 0x0A4D0002) {
		t.Error("свой адрес внутри туннеля отвергнут")
	}
	if SrcOK(p, 0x0A000205) {
		t.Error("чужой адрес принят — без этой проверки один пир подделывает трафик другого")
	}
}

// independentIPCsum — независимый подсчёт суммы заголовка IPv4: складываем 16-битные слова
// готового заголовка, включая поле суммы. У верного заголовка обязан выйти ноль.
func independentIPCsum(ip []byte, hl int) uint32 {
	var s uint32
	for i := 0; i < hl; i += 2 {
		s += uint32(ip[i])<<8 | uint32(ip[i+1])
	}
	for s>>16 != 0 {
		s = s&0xFFFF + s>>16
	}
	return s ^ 0xFFFF
}

func ipv4(ttl byte, proto byte, payload []byte) []byte {
	total := 20 + len(payload)
	ip := make([]byte, total)
	ip[0] = 0x45
	ip[2], ip[3] = byte(total>>8), byte(total)
	ip[8] = ttl
	ip[9] = proto
	copy(ip[12:16], []byte{10, 0, 0, 2})
	copy(ip[16:20], []byte{10, 0, 0, 3})
	copy(ip[20:], payload)
	c := ipCsum(ip, 20)
	ip[10], ip[11] = byte(c>>8), byte(c)
	return ip
}

func TestУменьшениеTTL(t *testing.T) {
	// Все значения TTL: сумма обязана сходиться на каждом, а не «обычно».
	for ttl := 0; ttl <= 255; ttl++ {
		ip := ipv4(byte(ttl), 6, make([]byte, 20))
		ok := TTLDec(ip)
		if ttl <= 1 {
			if ok {
				t.Fatalf("TTL %d понесён дальше — это петля в звезде", ttl)
			}
			continue
		}
		if !ok {
			t.Fatalf("TTL %d отвергнут", ttl)
		}
		if int(ip[8]) != ttl-1 {
			t.Fatalf("TTL %d не уменьшился", ttl)
		}
		if s := independentIPCsum(ip, 20); s != 0 {
			t.Fatalf("TTL %d: сумма заголовка не сошлась (%04x)", ttl, s)
		}
	}
	if TTLDec(make([]byte, 10)) {
		t.Error("обрезок пакета принят")
	}
	bad := ipv4(64, 6, nil)
	bad[0] = 0x60
	if TTLDec(bad) {
		t.Error("IPv6 принят там, где ждали IPv4")
	}
}

// tcpSYN — SYN с опциями: MSS, NOP, SACK-permitted. Ровно то, что строит настоящий стек.
func tcpSYN(mss int) []byte {
	tcp := make([]byte, 28)
	tcp[0], tcp[1] = 0xC0, 0x00 // порт источника
	tcp[2], tcp[3] = 0x01, 0xBB // 443
	tcp[12] = byte(28/4) << 4
	tcp[13] = 0x02 // SYN
	tcp[20], tcp[21] = 2, 4
	tcp[22], tcp[23] = byte(mss>>8), byte(mss)
	tcp[24] = 1 // NOP
	tcp[25], tcp[26] = 4, 2
	tcp[27] = 0 // конец списка
	return tcp
}

func independentTCPCsum(ip []byte) uint32 {
	hl := int(ip[0]&0x0F) * 4
	total := int(ip[2])<<8 | int(ip[3])
	tcp := ip[hl:total]
	var s uint32
	for i := 12; i < 20; i += 2 {
		s += uint32(ip[i])<<8 | uint32(ip[i+1])
	}
	s += 6 + uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		s += uint32(tcp[i])<<8 | uint32(tcp[i+1])
	}
	if len(tcp)&1 != 0 {
		s += uint32(tcp[len(tcp)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xFFFF + s>>16
	}
	return s ^ 0xFFFF
}

func TestПодрезкаMSS(t *testing.T) {
	const mtu = 1387
	limit := mtu - 40

	ip := ipv4(64, 6, tcpSYN(1460))
	if !MSSClamp(ip, mtu) {
		t.Fatal("MSS 1460 не подрезан — большие сегменты пропадали бы молча")
	}
	// Опция MSS лежит в первых байтах списка опций: заголовок IP (20) + заголовок TCP (20) + 2.
	got := int(ip[42])<<8 | int(ip[43])
	if got != limit {
		t.Errorf("MSS подрезан до %d, а предел %d (RFC 6691: без запаса на опции)", got, limit)
	}
	if s := independentTCPCsum(ip); s != 0 {
		t.Errorf("сумма TCP после правки не сошлась (%04x)", s)
	}

	// Меньший MSS не трогаем: подрезать вверх нельзя, это не «выравнивание».
	small := ipv4(64, 6, tcpSYN(536))
	if MSSClamp(small, mtu) {
		t.Error("MSS 536 переписан")
	}

	// Не SYN, не TCP, фрагмент, битая опция — всё это обязано остаться без правки и без паники.
	notSyn := ipv4(64, 6, tcpSYN(1460))
	notSyn[20+13] = 0x10 // только ACK
	if MSSClamp(notSyn, mtu) {
		t.Error("опция MSS поправлена в сегменте без SYN")
	}
	udp := ipv4(64, 17, tcpSYN(1460))
	if MSSClamp(udp, mtu) {
		t.Error("поправлен не TCP")
	}
	frag := ipv4(64, 6, tcpSYN(1460))
	frag[6], frag[7] = 0x00, 0x20 // смещение фрагмента не ноль
	if MSSClamp(frag, mtu) {
		t.Error("поправлен фрагмент, который заголовка TCP не несёт")
	}
	broken := ipv4(64, 6, tcpSYN(1460))
	broken[20+21] = 99 // длина опции за пределами заголовка
	if MSSClamp(broken, mtu) {
		t.Error("принята опция с длиной за пределами заголовка")
	}
	lying := ipv4(64, 6, tcpSYN(1460))
	lying[2], lying[3] = 0xFF, 0xFF // заявленная длина больше настоящей
	if MSSClamp(lying, mtu) {
		t.Error("принята завышенная длина в заголовке IP — это чтение за буфером")
	}
	for n := 0; n < 40; n++ {
		// Обрезки любой длины: паники быть не должно ни на одной.
		MSSClamp(ipv4(64, 6, tcpSYN(1460))[:n], mtu)
	}
}

func TestХешПотока(t *testing.T) {
	a := ipv4(64, 6, tcpSYN(1460))
	b := ipv4(63, 6, tcpSYN(1460)) // тот же поток, другой TTL
	if FlowHash(a) != FlowHash(b) {
		t.Error("TTL не должен влиять на выбор соединения: иначе пакеты одного потока разъедутся")
	}
	c := ipv4(64, 6, tcpSYN(1460))
	c[19] = 9 // другой адрес назначения
	if FlowHash(a) == FlowHash(c) {
		t.Error("разные потоки дали один хеш на маленьком наборе — это уже перекос раскладки")
	}
	// Фрагмент, кроме первого: порты недоступны, но поток обязан определяться адресами — иначе
	// фрагменты одного пакета уехали бы разными соединениями и не собрались бы никогда.
	f1 := ipv4(64, 6, tcpSYN(1460))
	f1[6], f1[7] = 0x00, 0x20
	f2 := ipv4(64, 6, tcpSYN(1400))
	f2[6], f2[7] = 0x00, 0x20
	if FlowHash(f1) != FlowHash(f2) {
		t.Error("фрагменты одного пакета получили разные хеши")
	}
	if FlowHash(make([]byte, 10)) != 0 {
		t.Error("обрезок обязан давать ноль, а не мусор")
	}

	// Раскладка по четырём соединениям обязана быть примерно ровной: перекос означал бы, что
	// одно ядро работает, а три стоят.
	var bins [4]int
	rng := rand.New(rand.NewSource(3))
	const N = 40000
	for i := 0; i < N; i++ {
		p := ipv4(64, 6, tcpSYN(1460))
		rng.Read(p[12:20])
		bins[FlowHash(p)%4]++
	}
	for i, v := range bins {
		if v < N/4-N/20 || v > N/4+N/20 {
			t.Errorf("соединение %d получило %d потоков из %d — раскладка перекошена", i, v, N)
		}
	}
}
