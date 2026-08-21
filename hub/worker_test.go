package hub

// Стенд одной сессии хаба: настоящее рукопожатие Noise IK и настоящие записи, но без единого
// сокета и без root. Сырой сокет и устройство подменены памятью, а сессия заводится через
// link.Accept напрямую — w.accept() открыл бы настоящий сырой сокет, а он требует прав.
//
// Стенд нужен не одному тесту: путь «сегмент → сборка записи → AEAD → кадр → маршрутизация»
// проверяется здесь целиком, и именно на нём видны находки, которых не видно по частям (кадр
// длиннее строки буфера, поддельный SYN в живую сессию, MTU из провода).

import (
	"context"
	"encoding/binary"
	"io"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/xyzmean/xsteer/conf"
	"github.com/xyzmean/xsteer/link"
	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/route"
	"github.com/xyzmean/xsteer/tun"
	"github.com/xyzmean/xsteer/wire"
)

// ---- подменённое окружение --------------------------------------------------

// fakeRaw — сырой сокет, которого нет: отправленные сегменты складываются в память.
type fakeRaw struct {
	local [4]byte
	sent  [][]byte
}

func (r *fakeRaw) Send(seg []byte) error {
	r.sent = append(r.sent, append([]byte(nil), seg...))
	return nil
}
func (r *fakeRaw) Recv([]byte) (int, error)             { return 0, io.EOF }
func (r *fakeRaw) WaitRead(time.Duration) (bool, error) { return false, nil }
func (r *fakeRaw) Local() [4]byte                       { return r.local }
func (r *fakeRaw) Close() error                         { return nil }

// payloadsSince склеивает нагрузку сегментов, отправленных начиная с индекса from.
func (r *fakeRaw) payloadsSince(from int) []byte {
	var out []byte
	for _, s := range r.sent[from:] {
		hl := int(s[12]>>4) * 4
		if len(s) > hl {
			out = append(out, s[hl:]...)
		}
	}
	return out
}

// flagsSince — флаги сегментов, отправленных начиная с индекса from.
func (r *fakeRaw) flagsSince(from int) []byte {
	var out []byte
	for _, s := range r.sent[from:] {
		out = append(out, s[13])
	}
	return out
}

// fakeDev — устройство TUN, которого нет: записанное складывается в память.
type fakeDev struct{ wrote [][]byte }

func (d *fakeDev) Read([]byte) (int, error)             { return 0, io.EOF }
func (d *fakeDev) WaitRead(time.Duration) (bool, error) { return false, nil }
func (d *fakeDev) Write(p []byte) (int, error) {
	d.wrote = append(d.wrote, append([]byte(nil), p...))
	return len(p), nil
}
func (d *fakeDev) Name() string     { return "xstest0" }
func (d *fakeDev) SetMTU(int) error { return nil }
func (d *fakeDev) Close() error     { return nil }

// sink — поток, в который сессия второго пира пишет свои записи. Читать из него нечего:
// проверяется только то, что записи ДОШЛИ до отправки, а не то, что кто-то их разберёт.
type sink struct{ recs [][]byte }

func (s *sink) Read([]byte) (int, error) { return 0, io.EOF }
func (s *sink) Write(p []byte) (int, error) {
	s.recs = append(s.recs, append([]byte(nil), p...))
	return len(p), nil
}

// ---- стенд ------------------------------------------------------------------

const (
	standListen = 443
	standISN    = uint32(0x10000000) // начальный номер пира: он же база смещений
	standSPort  = uint16(41000)
)

type stand struct {
	t   *testing.T
	h   *Hub
	w   *worker
	dev *fakeDev
	raw *fakeRaw

	s *session // сессия ПЕРВОГО пира на хабе (та, что принимает)
	k skey

	cliTX *noise.Keys // ключи пира на отправку: ими шифруются записи в хаб
	seq   uint32      // номер следующего байта, который пир отправит

	dst  *session // сессия ВТОРОГО пира: получатель трафика пир↔пир
	dsnk *sink
}

func standKeypair(t *testing.T, seed int64) (priv, pub [32]byte) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))
	r.Read(priv[:])
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pub[:], p)
	return
}

func ip4(a, b, c, d byte) uint32 {
	return uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
}

// newStand поднимает хаб с двумя пирами, проводит рукопожатие первого и оставляет его сессию в
// фазе phEst, готовой принимать записи.
func newStand(t *testing.T) *stand {
	t.Helper()
	cPriv, cPub := standKeypair(t, 1)
	hPriv, hPub := standKeypair(t, 2)
	_, p2Pub := standKeypair(t, 3)

	c := &conf.Conf{
		Addr: ip4(10, 0, 0, 1), AddrPlen: 24, ListenPort: standListen,
		Peers: []conf.Peer{
			{Pub: cPub, Allowed: []conf.Allowed{{Net: ip4(10, 0, 0, 2), Mask: 0xFFFFFFFF, Plen: 32}}},
			{Pub: p2Pub, Allowed: []conf.Allowed{{Net: ip4(10, 0, 0, 3), Mask: 0xFFFFFFFF, Plen: 32}}},
		},
	}
	h := &Hub{opt: Options{
		Conf: c, Sec: &conf.Secrets{Priv: hPriv, HasPriv: true},
		Logf: func(f string, a ...any) { t.Logf("hub: "+f, a...) },
	}}
	h.router = route.NewRouter(c.Peers)

	st := &stand{t: t, h: h, dev: &fakeDev{}, raw: &fakeRaw{local: [4]byte{198, 51, 100, 1}}}
	st.w = &worker{
		id: 0, n: 1, h: h, dev: st.dev,
		sess: make(map[skey]*session),
		row:  make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag),
		hbuf: make([]byte, 2048),
	}

	// SYN пира. Сессию заводим через link.Accept, а не через w.accept: тот открыл бы настоящий
	// сырой сокет.
	synSeg := st.mkSeg(standISN, link.SYN, nil)
	parsed, ok := link.ParseSeg(synSeg)
	if !ok {
		t.Fatal("свой же SYN не разобрался")
	}
	conn, err := link.Accept(st.raw, &parsed, standListen, 0x20000000)
	if err != nil {
		t.Fatalf("link.Accept: %v", err)
	}
	st.k = skey{addr: [4]byte{203, 0, 113, 9}, port: standSPort}
	st.s = &session{conn: conn, phase: phSyn, peer: -1, connID: -1}
	st.s.batchMax.Store(2)
	st.w.sess[st.k] = st.s
	st.seq = standISN + 1 // SYN занял один номер

	// Подтверждение нашего SYN-ACK: без него соединение остаётся в StateSynRcvd и данные не идут.
	st.feed(link.ACK, nil)

	// Рукопожатие: ClientHello одной записью, ответ хаба, подтверждение пира.
	cli := &noise.HS{}
	hello, err := cli.ClientHello(cPriv, hPub, "www.microsoft.com", wire.MTUDefault, 0, false, true,
		rand.New(rand.NewSource(11)))
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	before := len(st.raw.sent)
	st.feed(link.PSH|link.ACK, hello)
	if st.s.phase != phHS {
		t.Fatalf("после Hello фаза %d, ждали phHS — рукопожатие не разобрано", st.s.phase)
	}
	resp := st.raw.payloadsSince(before)
	cliTX, _, consumed, err := cli.ClientFinish(resp)
	if err != nil {
		t.Fatalf("ClientFinish: %v (ответ %d байт)", err, len(resp))
	}
	if consumed != len(resp) {
		t.Fatalf("пир израсходовал %d из %d байт ответа", consumed, len(resp))
	}
	fin, err := cli.ClientConfirm(cliTX)
	if err != nil {
		t.Fatalf("ClientConfirm: %v", err)
	}
	st.feed(link.PSH|link.ACK, fin)
	if st.s.phase != phEst {
		t.Fatalf("после подтверждения фаза %d, ждали phEst", st.s.phase)
	}
	st.cliTX = cliTX

	// Сессия ВТОРОГО пира: получатель трафика пир↔пир. Ведём её потоком — так не нужен ни второй
	// сырой сокет, ни разрезание на сегменты.
	st.dsnk = &sink{}
	_, _, dstTX, _ := standHandshake(t)
	st.dst = &session{
		st: wire.NewStream(st.dsnk), tx: dstTX, phase: phEst, peer: 1, connID: 0,
	}
	st.dst.mtu.Store(wire.MTUDefault)
	st.dst.batchMax.Store(1)
	h.peerSess[1][0].Store(st.dst)
	return st
}

// standHandshake — отдельное рукопожатие только ради пары ключей.
func standHandshake(t *testing.T) (cliTX, cliRX, hubTX, hubRX *noise.Keys) {
	t.Helper()
	cPriv, _ := standKeypair(t, 7)
	hPriv, hPub := standKeypair(t, 8)
	cli, hub := &noise.HS{}, &noise.HS{}
	hello, err := cli.ClientHello(cPriv, hPub, "www.microsoft.com", wire.MTUDefault, 0, false, true,
		rand.New(rand.NewSource(99)))
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.ServerRead(hPriv, hello, rand.New(rand.NewSource(98))); err != nil {
		t.Fatal(err)
	}
	resp, hubTX, hubRX, err := hub.ServerWrite(wire.MTUDefault)
	if err != nil {
		t.Fatal(err)
	}
	cliTX, cliRX, _, err = cli.ClientFinish(resp)
	if err != nil {
		t.Fatal(err)
	}
	return
}

// mkSeg собирает пакет от ПЕРВОГО пира стенда.
func (s *stand) mkSeg(seq uint32, flags byte, payload []byte) []byte {
	return segPkt([4]byte{203, 0, 113, 9}, standSPort, seq, flags, payload)
}

// segPkt собирает пакет так, как он приходит из сырого сокета: заголовок IP плюс сегмент. Источник
// задаётся параметрами: стенду нужны сегменты не только от первого пира — вторая сессия
// поддельного TCP на том же воркере приходит с другого адреса и порта.
func segPkt(src [4]byte, sport uint16, seq uint32, flags byte, payload []byte) []byte {
	dst := [4]byte{198, 51, 100, 1}
	tcp := make([]byte, 60+len(payload))
	opts := link.OptNone
	if flags&link.SYN != 0 {
		opts = link.OptScale
	}
	n := link.BuildSeg(tcp, src, dst, sport, standListen, seq, 1, flags, opts, payload)
	pkt := make([]byte, 20+n)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[20:], tcp[:n])
	return pkt
}

// feed отдаёт хабу один сегмент от пира и двигает номер.
func (s *stand) feed(flags byte, payload []byte) {
	s.t.Helper()
	seg, ok := link.ParseSeg(s.mkSeg(s.seq, flags, payload))
	if !ok {
		s.t.Fatal("сегмент не разобрался")
	}
	s.seq += uint32(len(payload))
	s.w.onSeg(&seg)
}

// feedRecord отправляет один кадр записью, разрезая её на сегменты по seg байт. Смещение для
// nonce — относительный номер первого байта записи, ровно как считает пир.
func (s *stand) feedRecord(frame []byte, segMax int) {
	s.t.Helper()
	s.feedRecordAs(frame, segMax, false)
}

// feedRecordAs — то же, но с выбором, кто пишет заголовок. raw означает «руками, без предела
// формата в RecBuild»: запись длиннее MaxRecord наш сборщик больше не соберёт, и это правильно, —
// но проверить, что её отвергает ПРИЁМНИК, всё равно надо. Иначе находка считалась бы закрытой не
// тем слоем: у отправителя стоит наш собственный ограничитель, а на публичный порт приезжает то,
// что прислал кто угодно.
func (s *stand) feedRecordAs(frame []byte, segMax int, raw bool) {
	s.t.Helper()
	rec := make([]byte, wire.RecHdr+len(frame)+wire.Tag)
	body := len(frame) + wire.Tag
	if raw {
		rec[0], rec[1], rec[2] = 0x17, 0x03, 0x03
		rec[3], rec[4] = byte(body>>8), byte(body)
	} else if err := wire.RecBuild(rec[:wire.RecHdr], body); err != nil {
		s.t.Fatalf("RecBuild(%d): %v", body, err)
	}
	copy(rec[wire.RecHdr:], frame)
	rel := wire.Rel(s.seq, standISN)
	if _, err := s.cliTX.Seal(rec[wire.RecHdr:], len(frame), rec[:wire.RecHdr], uint64(rel)); err != nil {
		s.t.Fatalf("Seal: %v", err)
	}
	for off := 0; off < len(rec); off += segMax {
		end := off + segMax
		if end > len(rec) {
			end = len(rec)
		}
		s.feed(link.PSH|link.ACK, rec[off:end])
	}
}

// ip4Frame — кадр IPv4 нужной длины, UDP внутри (чтобы не задевать подрезку MSS).
func ip4Frame(src, dst uint32, total int) []byte {
	p := make([]byte, total)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(total))
	p[8] = 64 // TTL
	p[9] = 17 // UDP
	binary.BigEndian.PutUint32(p[12:16], src)
	binary.BigEndian.PutUint32(p[16:20], dst)
	return p
}

// ---- находка 1: кадр длиннее предела -----------------------------------------

// TestКадрДлиннееПределаОтброшен: пир прислал кадр, который не влезает в путь пересылки.
//
// Строка буфера воркера — HdrRoom+MaxRecord+Tag = 8253 байта, а copy() в onFrame урезал кадр
// МОЛЧА: дальше sendTo брал срез row[HdrRoom : HdrRoom+plen+Tag] по урезанной длине. На кадре в
// 9000 байт это давало row[45:8269] при ёмкости 8253 — непойманная паника в горутине приёма и
// падение процесса хаба целиком, вместе со всеми пирами звезды.
//
// Здесь проверяется кадр 8176 байт — самый большой, который вообще способна доставить запись
// (MaxRecord за вычетом тега). Паники он не даёт, а вот в устройство или другому пиру уезжает как
// пакет с длиной, не равной заявленной в его же заголовке IP, — то есть находка та же и без
// падения. Кадр длиннее записи (9000 байт) сегодня отвергает уже wire.Reasm по пределу MaxRecord,
// поэтому проверка предела в самом хабе — второй слой: он не зависит от того, каким числом
// проверяет длину записи сборка.
//
// Законного кадра длиннее MTUDefault не бывает по построению: и клиент (client.go, stream.go), и
// сам хаб (tunLoop) читают устройство в буфер ровно MTUDefault, а проба пути ограничена тем же
// числом. Значит это либо порча, либо чужая реализация, и место ему в счётчике.
func TestКадрДлиннееПределаОтброшен(t *testing.T) {
	st := newStand(t)

	// Контроль: законный кадр той же дорогой доходит до второго пира. Без него проверка ниже
	// ничего не значила бы — «не дошло» вышло бы само.
	ok := ip4Frame(ip4(10, 0, 0, 2), ip4(10, 0, 0, 3), wire.MTUDefault)
	st.feedRecord(ok, 1400)
	if len(st.dsnk.recs) != 1 {
		t.Fatalf("законный кадр %d байт не дошёл до второго пира: записей %d",
			len(ok), len(st.dsnk.recs))
	}

	// Кадр во всю запись: 8176 = MaxRecord - Tag.
	const oversize = wire.MaxRecord - wire.Tag
	dropped := st.h.stats.dropped.Load()
	st.feedRecord(ip4Frame(ip4(10, 0, 0, 2), ip4(10, 0, 0, 3), oversize), 1400)

	if len(st.dsnk.recs) != 1 {
		t.Errorf("кадр %d байт уехал ко второму пиру: записей стало %d", oversize, len(st.dsnk.recs))
	}
	if len(st.dev.wrote) != 0 {
		t.Errorf("кадр %d байт записан в устройство (%d раз)", oversize, len(st.dev.wrote))
	}
	if got := st.h.stats.dropped.Load(); got == dropped {
		t.Errorf("кадр %d байт отброшен без счётчика: dropped остался %d", oversize, got)
	}

	// ГЛАВНЫЙ СЛУЧАЙ: тот же кадр через контейнер пачки. Здесь законно всё — запись не длиннее
	// MaxRecord, пачка собрана как положено, тег сходится, — а кадр внутри много больше MTUDefault.
	// Именно так многокилобайтный кадр доезжает до onFrame по совершенно законному пути и упирается
	// ровно в copy(), не завися ни от какого предела в сборке записи.
	pack := make([]byte, wire.MaxRecord-wire.Tag)
	n := wire.BatchBuild(pack, [][]byte{
		ip4Frame(ip4(10, 0, 0, 2), ip4(10, 0, 0, 3), 4000),
		ip4Frame(ip4(10, 0, 0, 2), ip4(10, 0, 0, 3), 4000),
	})
	if n == 0 {
		t.Fatal("контейнер пачки не собрался — стенд неверен")
	}
	dropped = st.h.stats.dropped.Load()
	st.feedRecord(pack[:n], 1400)
	if len(st.dsnk.recs) != 1 {
		t.Errorf("кадры 4000 байт из пачки уехали ко второму пиру: записей стало %d",
			len(st.dsnk.recs))
	}
	if len(st.dev.wrote) != 0 {
		t.Errorf("кадры 4000 байт из пачки записаны в устройство (%d раз)", len(st.dev.wrote))
	}
	if got := st.h.stats.dropped.Load(); got < dropped+2 {
		t.Errorf("оба кадра пачки обязаны попасть в счётчик: было %d, стало %d", dropped, got)
	}

	// И кадр длиннее записи. СВОЙ сборщик такую запись больше не соберёт — RecBuild мерит предел
	// формата, — поэтому заголовок здесь пишется руками: ровно так её пришлёт чужой или сломанный
	// отправитель, и отвергнуть её обязан приёмник, а не наша же проверка на выходе.
	st.feedRecordAs(ip4Frame(ip4(10, 0, 0, 2), ip4(10, 0, 0, 3), 9000), 1400, true)
	if len(st.dsnk.recs) != 1 || len(st.dev.wrote) != 0 {
		t.Errorf("кадр 9000 байт куда-то уехал: записей %d, записей в устройство %d",
			len(st.dsnk.recs), len(st.dev.wrote))
	}
}

// ---- находка 2: поддельный SYN в живую сессию --------------------------------

// TestПоддельныйSYNНеСбрасываетСессию: SYN без ACK по четвёрке РАБОТАЮЩЕЙ сессии.
//
// Такой сегмент не несёт ни байта аутентификации — его собирает кто угодно, кто знает адрес хаба
// и порт пира. До правки ветка SYN безусловно переписывала isnRX, а из него выводится смещение
// записи и nonce расшифровки: один посторонний пакет останавливал входящий поток пира до
// таймаута сессии (три минуты). Проверяем всё сразу: номер не тронут, поток продолжается, и в
// ответ ничего не отправлено (RST оборвал бы туннель НАСТОЯЩЕМУ пиру, адрес-то поддельный).
func TestПоддельныйSYNНеСбрасываетСессию(t *testing.T) {
	st := newStand(t)

	first := ip4Frame(ip4(10, 0, 0, 2), ip4(10, 0, 0, 3), 200)
	st.feedRecord(first, 1400)
	if len(st.dsnk.recs) != 1 {
		t.Fatalf("первая запись не дошла: записей %d", len(st.dsnk.recs))
	}

	isnWas := st.s.conn.ISNRX()
	phaseWas := st.s.phase
	before := len(st.raw.sent)

	// Поддельный SYN: адрес и порт те же, номер посторонний.
	spoof, ok := link.ParseSeg(st.mkSeg(0x7EEEEEEE, link.SYN, nil))
	if !ok {
		t.Fatal("поддельный SYN не разобрался")
	}
	st.w.onSeg(&spoof)

	if got := st.s.conn.ISNRX(); got != isnWas {
		t.Errorf("поддельный SYN переписал isnRX: было %#x, стало %#x", isnWas, got)
	}
	if st.s.phase != phaseWas {
		t.Errorf("поддельный SYN сменил фазу сессии: было %d, стало %d", phaseWas, st.s.phase)
	}
	if f := st.raw.flagsSince(before); len(f) != 0 {
		t.Errorf("на поддельный SYN отправлено %d сегментов (флаги %v) — ответа быть не должно",
			len(f), f)
	}

	// Главное: входящий поток продолжается.
	second := ip4Frame(ip4(10, 0, 0, 2), ip4(10, 0, 0, 3), 300)
	st.feedRecord(second, 1400)
	if len(st.dsnk.recs) != 2 {
		t.Errorf("после поддельного SYN входящий поток встал: записей %d, ждали 2",
			len(st.dsnk.recs))
	}
}

// ---- находка 4: нижняя граница объявленного MTU ------------------------------

// TestMTUИзПроводаПроверяетсяНаНиз: служебный кадр «дальше несём столько» с числом из провода.
//
// MTU сессии — это то, по чему запись режется на сегменты. Пир, назвавший 1, заставлял хаб резать
// каждую запись на сотни сегментов: шестидесятикратное умножение системных вызовов по своей же
// воле, а при совсем малых значениях запись не уходит вовсе. Ниже MTUFloor путь не опускает и сам
// пробой, поэтому меньшее значение — не «узкий путь», а непроверенное число из провода.
func TestMTUИзПроводаПроверяетсяНаНиз(t *testing.T) {
	st := newStand(t)
	s := st.s

	// Сначала законное значение: оно обязано примениться.
	pt := make([]byte, 3)
	wire.MTUBuild(pt, 1300)
	st.w.onCtl(s, pt)
	if got := s.mtu.Load(); got != 1300 {
		t.Fatalf("законный MTU 1300 не применился: mtu = %d", got)
	}

	for _, mv := range []int{1, 100, wire.MTUFloor - 1} {
		wire.MTUBuild(pt, mv)
		st.w.onCtl(s, pt)
		if got := s.mtu.Load(); got != 1300 {
			t.Errorf("MTU %d из провода принят: mtu стал %d, ждали прежний 1300", mv, got)
			s.mtu.Store(1300)
		}
	}

	// Ровно на границе — принимается: это законный узкий путь, а не мусор.
	wire.MTUBuild(pt, wire.MTUFloor)
	st.w.onCtl(s, pt)
	if got := s.mtu.Load(); got != wire.MTUFloor {
		t.Errorf("MTU ровно %d отвергнут: mtu = %d", wire.MTUFloor, got)
	}
}

// ---- находка 5: кадры IPv6 в маршрутизации -----------------------------------

// TestКадрIPv6Отброшен: маршрутизации IPv6 в хабе нет, и отказ обязан быть решением, а не
// совпадением.
//
// route разбирает кадр как IPv4: адрес источника читается по смещению 12, а у пакета IPv6 там
// лежит середина ЕГО адреса источника. Обычно такой кадр останавливает проверка права на адрес —
// но пир, описанный в конфигурации, может подобрать эти байты так, чтобы они попали в его
// разрешённый диапазон. Здесь это и сделано: до правки кадр IPv6 уезжал в устройство как пакет
// IPv4.
func TestКадрIPv6Отброшен(t *testing.T) {
	st := newStand(t)

	p := make([]byte, 80)
	p[0] = 0x60 // версия 6
	binary.BigEndian.PutUint16(p[4:6], 40)
	p[6] = 17 // UDP
	p[7] = 64 // hop limit
	// Байты 12..16 — середина адреса источника IPv6, и именно их route прочитает как адрес
	// источника IPv4. Кладём туда разрешённый пиру адрес.
	binary.BigEndian.PutUint32(p[12:16], ip4(10, 0, 0, 2))
	// Байты 16..20 — «адрес получателя» в глазах route: чужая сеть, то есть путь в устройство.
	binary.BigEndian.PutUint32(p[16:20], ip4(8, 8, 8, 8))

	dropped := st.h.stats.dropped.Load()
	st.feedRecord(p, 1400)

	if len(st.dev.wrote) != 0 {
		t.Errorf("кадр IPv6 записан в устройство как пакет IPv4 (%d раз)", len(st.dev.wrote))
	}
	if len(st.dsnk.recs) != 0 {
		t.Errorf("кадр IPv6 уехал другому пиру: записей %d", len(st.dsnk.recs))
	}
	if got := st.h.stats.dropped.Load(); got == dropped {
		t.Errorf("кадр IPv6 отброшен без счётчика: dropped остался %d", got)
	}
}

// ---- находка 6: общий буфер продолжения разрезанной записи --------------------

// standTCPPeer — ещё одна сессия ПОДДЕЛЬНОГО TCP на том же воркере: свой сырой сокет, своё
// соединение в StateEst, свои ключи.
//
// Нужна там, где проверяется общее МЕЖДУ сессиями (буферы воркера), а не содержимое записей:
// разбирать отправленное здесь никто не будет, поэтому и рукопожатие берётся готовой парой ключей.
// Сессия второго пира из newStand для этого не годится — она ведётся потоком, а поток не режет
// записи на сегменты и буфера продолжения не касается.
func standTCPPeer(t *testing.T, sport uint16, mtu int) (*session, *fakeRaw) {
	t.Helper()
	src := [4]byte{203, 0, 113, 10}
	raw := &fakeRaw{local: [4]byte{198, 51, 100, 1}}
	syn, ok := link.ParseSeg(segPkt(src, sport, standISN, link.SYN, nil))
	if !ok {
		t.Fatal("SYN второй сессии не разобрался")
	}
	conn, err := link.Accept(raw, &syn, standListen, 0x30000000)
	if err != nil {
		t.Fatalf("link.Accept: %v", err)
	}
	ack, ok := link.ParseSeg(segPkt(src, sport, standISN+1, link.ACK, nil))
	if !ok {
		t.Fatal("ACK второй сессии не разобрался")
	}
	if _, err := conn.OnSeg(&ack); err != nil {
		t.Fatalf("OnSeg(ACK): %v", err)
	}
	if conn.State() != link.StateEst {
		t.Fatalf("вторая сессия не поднялась: состояние %d", conn.State())
	}
	_, _, hubTX, _ := standHandshake(t)
	d := &session{conn: conn, tx: hubTX, phase: phEst, peer: 1, connID: 1}
	d.mtu.Store(int32(mtu))
	d.batchMax.Store(1)
	return d, raw
}

// TestОтправкаВДвеСессииНеДелитБуфер: два одновременных sendTo ОДНОГО воркера в РАЗНЫЕ сессии.
//
// Буфер продолжения разрезанной записи принадлежал воркеру, а защищён был замком сессии-получателя.
// У двух получателей это два разных замка, поэтому один и тот же буфер писали одновременно: хвост
// записи уезжал пиру с чужими байтами, у него не сходился тег AEAD, и запись пропадала молча.
// Достижимо штатно и без всякой злой воли — кадр предельного размера пиру с меньшим согласованным
// MTU режется на сегменты, а цикл TUN в это же время везёт пачку другому пиру.
//
// Рядом в коде замысел уже был записан: row в tunLoop заведён локально в горутине именно затем,
// чтобы не делить его с горутиной приёма. Буфер продолжения из этого замысла просто выпал.
//
// Тест смотрит детектором гонок, поэтому строки буфера у горутин РАЗНЫЕ — иначе детектор поймал бы
// row и до буфера продолжения не дошёл бы.
func TestОтправкаВДвеСессииНеДелитБуфер(t *testing.T) {
	st := newStand(t)
	// Пир с меньшим MTU: у него запись режется на большее число сегментов, то есть в буфер
	// продолжения пишется чаще.
	d2, raw2 := standTCPPeer(t, standSPort+1, wire.MTUFloor)

	// Запись, которая гарантированно режется у обоих: 4000 + 21 больше и 1460 (MTUDefault),
	// и 1221 (MTUFloor).
	const plen = 4000
	send := func(d *session, fill byte) {
		row := make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag)
		for i := range row {
			row[i] = fill
		}
		for i := 0; i < 100; i++ {
			st.w.sendTo(d, row, plen)
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); send(st.s, 0xA5) }()
	go func() { defer wg.Done(); send(d2, 0x5A) }()
	wg.Wait()

	// Контроль: обе сессии действительно отправляли, то есть гонка была на живом пути, а не на
	// ветке отказа.
	if got := st.h.stats.txPkts.Load(); got != 200 {
		t.Errorf("отправлено записей %d, ждали 200 — путь до буфера продолжения не пройден", got)
	}
	if got := st.h.stats.dropped.Load(); got != 0 {
		t.Errorf("отброшено %d записей — отправка не дошла до разрезания", got)
	}
	// И главное для этого теста: записи ДЕЙСТВИТЕЛЬНО резались. Без разрезания буфер продолжения
	// не трогается вовсе, и проверка стала бы пустой, ничего об этом не сказав.
	if got := len(raw2.sent) - 1; got < 200 { // минус SYN-ACK
		t.Errorf("пир с MTU %d получил %d сегментов на 100 записей — разрезания не было",
			wire.MTUFloor, got)
	}
}

// ---- находка 7: потолок согласованного MTU -----------------------------------

// TestMTUИзПроводаЗажатПотолком: тот же служебный кадр, но с числом СВЕРХУ.
//
// Нижнюю границу проверяли (находка 4), верхней не было: значение из провода зажималось только
// числом из конфигурации, а конфигурация принимает MTU до 1500. При хабе с MTU 1480..1500 и пире,
// назвавшем столько же, maxSeg выходил больше предельного сегмента канала, и КАЖДАЯ разрезаемая
// запись отваливалась в «мал буфер под продолжение записи» — то есть туннель нёс мелкие пакеты и
// молча терял крупные, худший класс отказов в диагностике.
//
// Потолок один и тот же и для числа из провода, и для числа из конфигурации: MTUDefault — это
// 1500 минус наши накладные, больше физически не влезает в кадр Ethernet.
func TestMTUИзПроводаЗажатПотолком(t *testing.T) {
	st := newStand(t)
	st.h.opt.Conf.MTU = wire.LinkMax // хаб настроен по MTU КАНАЛА, а не туннеля
	s := st.s

	pt := make([]byte, 3)
	for _, mv := range []int{wire.MTUDefault + 1, 1480, wire.LinkMax, 9000} {
		wire.MTUBuild(pt, mv)
		st.w.onCtl(s, pt)
		if got := s.mtu.Load(); got != wire.MTUDefault {
			t.Errorf("MTU %d из провода принят как есть: mtu = %d, ждали потолок %d",
				mv, got, wire.MTUDefault)
		}
	}

	// И главное: с таким MTU разрезаемая запись обязана уехать, а не попасть в счётчик отброшенных.
	row := make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag)
	dropped := st.h.stats.dropped.Load()
	before := len(st.raw.sent)
	st.w.sendTo(s, row, 4000)
	if got := st.h.stats.dropped.Load(); got != dropped {
		t.Errorf("разрезаемая запись отброшена при согласованном MTU %d: dropped %d → %d",
			s.mtu.Load(), dropped, got)
	}
	if n := len(st.raw.sent) - before; n < 2 {
		t.Errorf("запись 4000 байт уехала %d сегментами — разрезания не было", n)
	}
}

// ---- находка 8: поля сессии против замка сессии -------------------------------

// feedDev — устройство TUN, которое отдаёт один и тот же пакет столько раз, сколько попросят.
//
// fakeDev для этого не годится: он возвращает io.EOF, то есть цикл TUN у него не делает ни одного
// круга, а проверять надо ровно круги — чтение поля получателя стоит внутри набора пачки.
type feedDev struct {
	pkt   []byte
	reads atomic.Int64
}

func (d *feedDev) Read(p []byte) (int, error) {
	d.reads.Add(1)
	return copy(p, d.pkt), nil
}
func (d *feedDev) WaitRead(time.Duration) (bool, error) { return true, nil }
func (d *feedDev) Write(p []byte) (int, error)          { return len(p), nil }
func (d *feedDev) Name() string                         { return "xsfeed0" }
func (d *feedDev) SetMTU(int) error                     { return nil }
func (d *feedDev) Close() error                         { return nil }

// udpPkt — кадр из устройства: пакет IPv4 к внутреннему адресу второго пира. Протокол UDP взят
// намеренно — подрезка MSS его не касается, и в проверке остаётся только то, что проверяется.
func udpPkt(dst uint32, n int) []byte {
	pkt := make([]byte, n)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(n))
	pkt[8] = 64
	pkt[9] = 17
	binary.BigEndian.PutUint32(pkt[12:16], ip4(10, 0, 0, 2))
	binary.BigEndian.PutUint32(pkt[16:20], dst)
	return pkt
}

// TestПоляСессииЧитаютсяСоСвоимЗамком: цикл TUN одного воркера против onCtl владельца сессии.
//
// mtu и batchMax — поля СЕССИИ, и правит их владелец: onCtl по служебному кадру пира, обслуживание
// по обратной связи о сборке. А читает их ОТПРАВКА, то есть любой воркер: цикл TUN смотрит на
// batchMax получателя, набирая пачку, и на его mtu, подрезая MSS; маршрутизация пир↔пир смотрит на
// mtu обоих концов. Замок у сессии для этого есть — тот самый, под которым идёт вся отправка, — но
// ни чтение, ни запись его не брали. Это тот же разрыв «поле сессии против замка сессии», что и у
// буфера продолжения записи, только на словах машинного размера: порчи значения на amd64 и arm64
// не будет, но «новый MTU применился к половине пакетов пачки» возможно, и детектор гонок это
// пометит, как только оба пути окажутся в одном тесте.
//
// Тест и есть этот тест. Смотреть его надо под -race: без детектора он зелёный всегда.
func TestПоляСессииЧитаютсяСоСвоимЗамком(t *testing.T) {
	st := newStand(t)
	// Устройство, отдающее пакеты второму пиру: их получателем будет st.dst, а его поля правит
	// вторая горутина. Своё устройство и у хаба — по нему обслуживание MTU трогает настройку.
	dev := &feedDev{pkt: udpPkt(ip4(10, 0, 0, 3), 100)}
	st.w.dev = dev
	st.h.dev = []tun.Device{dev}

	// Владелец сессии второго пира — ДРУГОЙ воркер: у хаба это так и есть, сессия лежит в таблице
	// того, кому её отдал фильтр раскладки.
	w2 := &worker{id: 1, n: 2, h: st.h, sess: make(map[skey]*session),
		row: make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag)}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); st.w.tunLoop(ctx) }()
	go func() {
		defer wg.Done()
		defer cancel()
		mtuFrame := make([]byte, 3)
		lossFrame := make([]byte, 8)
		ln := wire.LossBuild(lossFrame, 3)
		for i := 0; i < 300; i++ {
			// Пир перепробовал путь и называет новый размер — сюда же приходит и обратная связь
			// «записи не собираются», схлопывающая пачку.
			wire.MTUBuild(mtuFrame, wire.MTUFloor+i%200)
			w2.onCtl(st.dst, mtuFrame)
			w2.onCtl(st.dst, lossFrame[:ln])
		}
	}()
	wg.Wait()

	// Контроль: цикл TUN действительно делал круги, то есть чтение полей получателя произошло.
	if got := dev.reads.Load(); got < 100 {
		t.Errorf("цикл TUN прочитал устройство %d раз — путь до полей сессии не пройден", got)
	}
	if got := st.h.stats.txPkts.Load(); got == 0 {
		t.Error("во вторую сессию не ушло ни одной записи — отправка не состоялась")
	}
}

// ---- стенд вытеснения -------------------------------------------------------
//
// Здесь не нужны ни ключи, ни записи: проверяется одно решение — кого accept забирает при полной
// таблице. Поэтому сессии заводятся голыми, с настоящим link.Conn на памяти и нужной фазой.

// standEvictSess — сессия поддельного TCP без рукопожатия: только фаза и время последнего приёма.
func standEvictSess(t *testing.T, sport uint16, phase int) *session {
	t.Helper()
	raw := &fakeRaw{local: [4]byte{198, 51, 100, 1}}
	syn, ok := link.ParseSeg(segPkt([4]byte{203, 0, 113, 20}, sport, standISN, link.SYN, nil))
	if !ok {
		t.Fatal("SYN стенда вытеснения не разобрался")
	}
	conn, err := link.Accept(raw, &syn, standListen, 0x40000000)
	if err != nil {
		t.Fatalf("link.Accept: %v", err)
	}
	s := &session{conn: conn, phase: phase, peer: -1, connID: -1}
	s.batchMax.Store(1)
	return s
}

// standEvictWorker — воркер с таблицей ровно на n сессий и без единого сокета.
func standEvictWorker(t *testing.T, n int) *worker {
	t.Helper()
	h := &Hub{opt: Options{
		Conf: &conf.Conf{Addr: ip4(10, 0, 0, 1), AddrPlen: 24, ListenPort: standListen},
		Logf: func(f string, a ...any) { t.Logf("hub: "+f, a...) },
	}}
	return &worker{
		id: 0, n: 1, h: h, dev: &fakeDev{},
		sess:    make(map[skey]*session),
		row:     make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag),
		hbuf:    make([]byte, 2048),
		sessMax: n,
	}
}

// fillEst забивает таблицу воркера подтверждёнными сессиями и возвращает их ключи.
func fillEst(t *testing.T, w *worker, n int) []skey {
	t.Helper()
	keys := make([]skey, n)
	for i := 0; i < n; i++ {
		port := standSPort + uint16(100+i)
		keys[i] = skey{addr: [4]byte{203, 0, 113, 20}, port: port}
		w.sess[keys[i]] = standEvictSess(t, port, phEst)
	}
	return keys
}

// TestПолнаяТаблицаЖивыхСессийНеПускаетНовогоПира: посторонний SYN не сносит работающий туннель.
//
// Сессия заводится на первом же поддельном SYN, без всякой проверки. Правило вытеснения брало
// сперва самую давнюю НЕподтверждённую — и это защищало от потока SYN, — но при таблице из одних
// подтверждённых сессий вторая ветка забирала «самую давнюю вообще», то есть живой туннель,
// которому могло быть полчаса от роду и который молчал доли секунды. Один SYN с постороннего
// хоста в момент, когда таблица полна, стоил пиру разрыва и нового рукопожатия.
//
// Теперь подтверждённую можно забрать, только если она молчит дольше evictIdleMS. Молодая и живая
// не забирается — новому пиру отказывают.
func TestПолнаяТаблицаЖивыхСессийНеПускаетНовогоПира(t *testing.T) {
	w := standEvictWorker(t, 3)
	keys := fillEst(t, w, 3)

	nk := skey{addr: [4]byte{203, 0, 113, 21}, port: standSPort + 200}
	syn, ok := link.ParseSeg(segPkt(nk.addr, nk.port, standISN, link.SYN, nil))
	if !ok {
		t.Fatal("SYN нового пира не разобрался")
	}
	w.accept(nk, &syn)

	if _, ok := w.sess[nk]; ok {
		t.Error("новая сессия принята при полной таблице живых — кого-то из живых для неё выселили")
	}
	if len(w.sess) != 3 {
		t.Errorf("в таблице %d сессий, было 3 — состав изменился", len(w.sess))
	}
	for i, k := range keys {
		s, ok := w.sess[k]
		if !ok {
			t.Errorf("живая сессия %d исчезла из таблицы", i)
			continue
		}
		if s.phase != phEst {
			t.Errorf("живая сессия %d в фазе %d — её освободили", i, s.phase)
		}
	}
}

// TestПочтиМёртваяСессияВытесняется: правило отказа не превращается в вечный запрет.
//
// Обратный край того же решения. Сессия, молчащая дольше срока, живой уже не считается: её место
// новому пиру отдают, иначе одна брошенная сессия навсегда закрывала бы вход. Порог здесь взят
// маленький — минуту тест ждать не может, — а проверяется само правило «дольше срока — забираем,
// и забираем именно самую давнюю».
func TestПочтиМёртваяСессияВытесняется(t *testing.T) {
	w := standEvictWorker(t, 3)

	// Молчащая: заводится первой и после паузы оказывается самой давней в таблице.
	oldKey := skey{addr: [4]byte{203, 0, 113, 20}, port: standSPort + 300}
	w.sess[oldKey] = standEvictSess(t, oldKey.port, phEst)
	const quiet = 30 * time.Millisecond
	time.Sleep(quiet)
	fresh := fillEst(t, w, 2)

	if !w.evict(quiet.Milliseconds() / 2) {
		t.Fatal("сессия, молчащая дольше срока, не вытеснена — место не освободилось")
	}
	if _, ok := w.sess[oldKey]; ok {
		t.Error("вытеснили не давно молчавшую сессию")
	}
	for i, k := range fresh {
		if _, ok := w.sess[k]; !ok {
			t.Errorf("вытеснена свежая сессия %d вместо давно молчавшей", i)
		}
	}
}

// TestНеподтверждённаяВытесняетсяПервой: срок молчания не отменяет приоритета.
//
// Срок относится только к подтверждённым. Неподтверждённая уходит первой и без всякого срока —
// иначе поток SYN с меняющихся портов забивал бы таблицу молодыми сессиями, которые по новому
// правилу трогать нельзя, и хаб перестал бы принимать кого бы то ни было. То есть проверка ровно
// на то, что лечение одного отказа в обслуживании не завело другой.
func TestНеподтверждённаяВытесняетсяПервой(t *testing.T) {
	w := standEvictWorker(t, 3)
	est := fillEst(t, w, 2)
	// Неподтверждённая — САМАЯ СВЕЖАЯ в таблице: по времени молчания она последняя в очереди на
	// вытеснение, и забрать её можно только по фазе.
	rawKey := skey{addr: [4]byte{203, 0, 113, 20}, port: standSPort + 400}
	w.sess[rawKey] = standEvictSess(t, rawKey.port, phSyn)

	if !w.evict(evictIdleMS) {
		t.Fatal("неподтверждённая сессия не вытеснена — новый пир не принят из-за чужого SYN")
	}
	if _, ok := w.sess[rawKey]; ok {
		t.Error("неподтверждённая осталась в таблице — вытеснили не её")
	}
	for i, k := range est {
		if _, ok := w.sess[k]; !ok {
			t.Errorf("подтверждённая сессия %d вытеснена вперёд неподтверждённой", i)
		}
	}
}
