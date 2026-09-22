package client

// Стенд режима потока: настоящий клиентский streamSession против заглушки хаба на петле.
//
// ЗАЧЕМ ПЕТЛЯ, А НЕ net.Pipe. Отказы, ради которых стенд заведён, живут в свойствах настоящего
// сокета: соединение, которое ядро держит открытым, пока другая сторона молчит, и чтение, которое
// блокирует без срока. У пары в памяти нет ни буфера отправки, ни подтверждений ядра, и «хаб
// замолчал» на ней выглядело бы иначе, чем в жизни. Петля не требует прав и не зависит от сети.
//
// Заглушка делает ровно то, что хаб в hub/stream.go, и ничего сверх: рукопожатие Noise IK, приём
// записей, эхо на пробу. Молчать её можно заставить на ходу — это и есть «хаб умер, а ядро об этом
// не знает»: соединение цело, подтверждения TCP идут, записей в ответ нет.

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/xyzmean/xsteer/conf"
	"github.com/xyzmean/xsteer/link"
	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/tun"
	"github.com/xyzmean/xsteer/wire"
)

// memDev — устройство TUN в памяти. Пакеты, которые клиент «прочитает из системы», кладутся в
// очередь in; то, что клиент записал в устройство, считается и выбрасывается.
//
// flood — вместо очереди отдавать пакет IPv4 на каждое чтение: устройство, читаемое всегда,
// то есть односторонняя отдача наружу (закачка, раздача).
type memDev struct {
	mu     sync.Mutex
	in     [][]byte
	flood  bool
	wrote  atomic.Int64
	closed atomic.Bool
}

func (d *memDev) push(p []byte) {
	d.mu.Lock()
	d.in = append(d.in, append([]byte(nil), p...))
	d.mu.Unlock()
}

func (d *memDev) Read(p []byte) (int, error) {
	if d.closed.Load() {
		return 0, errors.New("устройство закрыто")
	}
	if d.flood {
		// Не каждое чтение: пачку надо чем-то кончать, иначе streamOut соберёт её до предела
		// записи на каждом круге и тест превратится в замер скорости петли.
		time.Sleep(time.Millisecond)
		return copy(p, ip4Pkt(200)), nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.in) == 0 {
		return 0, tun.ErrAgain
	}
	n := copy(p, d.in[0])
	d.in = d.in[1:]
	return n, nil
}

func (d *memDev) WaitRead(timeout time.Duration) (bool, error) {
	if d.flood {
		return true, nil
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		d.mu.Lock()
		n := len(d.in)
		d.mu.Unlock()
		if n > 0 {
			return true, nil
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false, nil
}

func (d *memDev) Write(p []byte) (int, error) { d.wrote.Add(1); return len(p), nil }
func (d *memDev) Flush() error                { return nil }
func (d *memDev) Name() string                { return "xsmem0" }
func (d *memDev) SetMTU(int) error            { return nil }
func (d *memDev) Close() error                { d.closed.Store(true); return nil }

// ip4Pkt — пакет IPv4 длиной n с правдоподобным заголовком (UDP, не TCP: подрезке MSS в нём
// делать нечего).
func ip4Pkt(n int) []byte {
	p := make([]byte, n)
	p[0] = 0x45
	p[2], p[3] = byte(n>>8), byte(n)
	p[8] = 64
	p[9] = 17
	copy(p[12:16], []byte{10, 7, 0, 2})
	copy(p[16:20], []byte{10, 7, 0, 1})
	return p
}

// stubHub — заглушка хаба режима потока на петле.
type stubHub struct {
	t    *testing.T
	ln   net.Listener
	priv [32]byte
	pub  [32]byte

	// mute — перестать отвечать записями. Соединение при этом живо, чтение идёт: ядро
	// подтверждает принятое, и со стороны клиента не видно ничего, кроме тишины.
	mute atomic.Bool
	// conns — сколько соединений прошло рукопожатие.
	conns atomic.Int64

	mu sync.Mutex
	// kinds — первые байты кадров, пришедших от клиента (для пачки — каждого кадра в ней).
	kinds []byte
}

func newStubHub(t *testing.T) *stubHub {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("петля: %v", err)
	}
	h := &stubHub{t: t, ln: ln}
	r := rand.New(rand.NewSource(41))
	r.Read(h.priv[:])
	p, err := curve25519.X25519(h.priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(h.pub[:], p)
	t.Cleanup(func() { ln.Close() })
	go h.serve()
	return h
}

func (h *stubHub) port() int { return h.ln.Addr().(*net.TCPAddr).Port }

func (h *stubHub) serve() {
	for {
		nc, err := h.ln.Accept()
		if err != nil {
			return
		}
		go h.conn(nc)
	}
}

// conn — одно соединение: то же рукопожатие, что hub.streamConn, и приём записей до обрыва.
func (h *stubHub) conn(nc net.Conn) {
	defer nc.Close()
	st := wire.NewStream(nc)
	var hdr [wire.RecHdr]byte
	if err := st.ReadFull(hdr[:]); err != nil {
		return
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	rec := make([]byte, wire.RecHdr+n)
	copy(rec, hdr[:])
	if err := st.ReadFull(rec[wire.RecHdr:]); err != nil {
		return
	}
	hs := &noise.HS{}
	defer hs.Wipe()
	if err := hs.ServerRead(h.priv, rec, nil); err != nil {
		h.t.Errorf("заглушка: Hello не разобрался: %v", err)
		return
	}
	out, tx, rx, err := hs.ServerWrite(wire.MTUDefault)
	if err != nil {
		h.t.Errorf("заглушка: ответ не собрался: %v", err)
		return
	}
	if err := st.WriteRaw(out); err != nil {
		return
	}
	var chdr [wire.RecHdr]byte
	if err := st.ReadFull(chdr[:]); err != nil {
		return
	}
	cn := int(chdr[3])<<8 | int(chdr[4])
	cbuf := make([]byte, wire.RecHdr+cn)
	copy(cbuf, chdr[:])
	if err := st.ReadFull(cbuf[wire.RecHdr:]); err != nil {
		return
	}
	if _, err := hs.ServerConfirm(rx, cbuf); err != nil {
		h.t.Errorf("заглушка: подтверждение не сошлось: %v", err)
		return
	}
	tx.EnableEpochs()
	rx.EnableEpochs()
	h.conns.Add(1)

	row := make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag)
	send := &Client{} // streamSend от клиента не зависит: только поток и ключи
	for {
		body, rhdr, rel, err := st.ReadRecord()
		if err != nil {
			return
		}
		pt, err := rx.Open(body, rhdr, rel)
		if err != nil {
			h.t.Errorf("заглушка: запись не расшифровалась: %v", err)
			return
		}
		note := func(f []byte) {
			if len(f) > 0 {
				h.mu.Lock()
				h.kinds = append(h.kinds, f[0])
				h.mu.Unlock()
			}
		}
		if len(pt) > 0 && pt[0] == wire.CtlBatch {
			wire.BatchIter(pt, note)
		} else {
			note(pt)
		}
		if h.mute.Load() {
			continue
		}
		// Эхо на пробу — единственное, чем хаб отвечает сам по себе.
		if psz := wire.ProbeSize(pt); psz > 0 {
			pn := wire.PackBuild(row[wire.HdrRoom:], psz)
			if err := send.streamSend(st, tx, row, pn); err != nil {
				return
			}
		}
	}
}

// ipKinds — версии IP кадров, дошедших до заглушки (служебные кадры не в счёт).
func (h *stubHub) ipKinds() (v4, other int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, k := range h.kinds {
		switch {
		case k <= 0x0F: // служебный
		case k>>4 == 4:
			v4++
		default:
			other++
		}
	}
	return
}

// standStreamClient — клиент, которому достаточно полей для streamSession к заглушке.
func standStreamClient(t *testing.T, h *stubHub) *Client {
	t.Helper()
	var sec conf.Secrets
	r := rand.New(rand.NewSource(42))
	r.Read(sec.Priv[:])
	sec.HasPriv = true
	cf := &conf.Conf{SNI: "www.microsoft.com", Peers: []conf.Peer{{
		Pub: h.pub, Endpoint: "127.0.0.1", EndpointPort: h.port(), Keepalive: 25,
	}}}
	return &Client{
		opt: Options{Conf: cf, Sec: &sec, Stream: true, StreamPort: h.port(),
			Logf: func(f string, a ...any) { t.Logf("клиент: "+f, a...) }},
		hub: hubInfo{pub: h.pub, port: h.port(), str: h.ln.Addr().String()},
	}
}

// runStream поднимает streamSession в горутине; канал отдаёт её итог.
func runStream(t *testing.T, c *Client, dev tun.Device) (<-chan error, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	fin := make(chan struct{})
	go func() { done <- c.streamSession(ctx, 0, dev); close(fin) }()
	deadline := time.Now().Add(5 * time.Second)
	for c.stats.up.Load() == 0 {
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("сессия потока не поднялась за пять секунд")
		}
		select {
		case err := <-done:
			cancel()
			t.Fatalf("сессия потока кончилась, не поднявшись: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-fin:
		case <-time.After(3 * time.Second):
			t.Error("сессия потока не ушла за три секунды после отмены")
		}
	})
	return done, cancel
}

// alive — сессия ещё идёт спустя d.
func alive(done <-chan error, d time.Duration) (bool, error) {
	select {
	case err := <-done:
		return false, err
	case <-time.After(d):
		return true, nil
	}
}

// ---- смена поколения сети ------------------------------------------------------------------

// TestПотокПереподнимаетсяНаСменеСети: NetChanged обязан рвать сессию потока.
//
// На телефоне клиент работает только потоком, а поколение сети читал только ход времени
// поддельного TCP (timeLoop). Сессия потока висит в блокирующем ReadRecord без срока, и после
// пробуждения телефона или смены Wi-Fi на LTE туннель оставался «поднятым» на старом сокете, пока
// ядро не сдастся по повторам (минуты). Здесь хаб жив и отвечает, то есть сессию рвёт ТОЛЬКО смена
// поколения — и без неё рвать нельзя.
func TestПотокПереподнимаетсяНаСменеСети(t *testing.T) {
	t.Parallel()
	h := newStubHub(t)
	c := standStreamClient(t, h)
	done, _ := runStream(t, c, &memDev{})

	if ok, err := alive(done, 700*time.Millisecond); !ok {
		t.Fatalf("сессия оборвалась без смены сети: %v", err)
	}
	c.NetChanged()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "сеть изменилась") {
			t.Errorf("сессия кончилась с %v, ждали причину «сеть изменилась»", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("после NetChanged сессия потока жива две секунды: поколение сети поток не читает")
	}
}

// ---- мёртвый хаб: шлём, а в ответ тишина (I-134) -------------------------------------------

// probes — сколько проб живости дошло до заглушки.
func (h *stubHub) probes() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, k := range h.kinds {
		if k == wire.CtlProbe {
			n++
		}
	}
	return n
}

// TestПотокПризнаётМолчащийХаб: хаб перестал отвечать, а соединение для ядра цело.
//
// У реализации на C правило есть (xsclient.c, stream_main: «шлём после того, как получили, и
// тишина дольше XSC_DEAD_MS»), у пира на Go его не было в потоке никак: срок чтения снят после
// рукопожатия, и мёртвый хаб замечало только ядро, исчерпав повторы, — минуты вместо восьми
// секунд. Заглушка здесь продолжает ЧИТАТЬ, то есть ядро подтверждает каждую запись и ошибки
// отправки не будет: сессию обязан оборвать сам клиент по тишине.
func TestПотокПризнаётМолчащийХаб(t *testing.T) {
	t.Parallel()
	h := newStubHub(t)
	c := standStreamClient(t, h)
	done, _ := runStream(t, c, &memDev{})

	h.mute.Store(true)
	began := time.Now()
	select {
	case err := <-done:
		took := time.Since(began)
		if took < link.DeadMS*time.Millisecond-streamProbeMS*time.Millisecond {
			t.Errorf("сессия оборвалась через %v — раньше порога %d мс", took, link.DeadMS)
		}
		if err == nil || !strings.Contains(err.Error(), "молчит") {
			t.Errorf("сессия кончилась с %v, ждали причину «молчит»", err)
		}
	case <-time.After(link.DeadMS*time.Millisecond + 4*time.Second):
		t.Fatalf("хаб молчит %d мс, а сессия потока жива: мёртвый хаб не признан",
			link.DeadMS+4000)
	}
}

// TestПотокНаОдностороннейОтдачеЖив: устройство читаемо всегда, хаб жив и отвечает только эхом.
//
// Порядок правки из I-134, и он жёсткий: проба живости у Go уходила ТОЛЬКО из ветки простоя
// устройства, поэтому на односторонней отдаче (закачка наверх) проб не было, эха не было — и
// правило «тишина при активной отправке» оборвало бы ЖИВУЮ сессию. Проба обязана уходить по
// времени, а не по простою, как в C; и тогда сессия обязана пережить порог.
func TestПотокНаОдностороннейОтдачеЖив(t *testing.T) {
	t.Parallel()
	h := newStubHub(t)
	c := standStreamClient(t, h)
	done, _ := runStream(t, c, &memDev{flood: true})

	if ok, err := alive(done, link.DeadMS*time.Millisecond+3*time.Second); !ok {
		t.Fatalf("на односторонней отдаче к живому хабу сессия оборвалась: %v", err)
	}
	if n := h.probes(); n < 3 {
		t.Errorf("за %d мс непрерывной отдачи до хаба дошло проб: %d — проба уходит только на простое",
			link.DeadMS+3000, n)
	}
}

// TestСудьяПотокаНеСчитаетНашуНезанятость: тишина, в которую НАС не исполняли, путь не хоронит.
//
// Телефон в дремоте замораживает процесс целиком. После пробуждения от последнего ответа хаба
// прошли минуты, а последняя проба ушла позже него — голое сравнение с порогом объявило бы путь
// мёртвым первым же тиком, хотя путь никто и не проверял. То же правило, что link.Conn.tick и
// xs_conn_tick: перерыв между тиками дольше секунды в тишину не засчитывается.
func TestСудьяПотокаНеСчитаетНашуНезанятость(t *testing.T) {
	var j streamJudge
	const t0 = int64(1_000_000)
	rx, tx := t0, t0+100 // хаб ответил, мы отправили пробу
	now := t0 + 100
	for ; now < t0+2000; now += 200 {
		if j.dead(now, tx, rx) {
			t.Fatalf("мертво через %d мс тишины при пороге %d", now-rx, link.DeadMS)
		}
	}
	// Дремота: пять минут нас не исполняли.
	now += 300_000
	if j.dead(now, tx, rx) {
		t.Fatal("после пяти минут дремоты путь объявлен мёртвым первым же тиком")
	}
	// Проснулись, шлём, хаб молчит: теперь тишина наша, и порог обязан сработать.
	var died int64
	for step := 0; step < 100; step++ {
		now += 200
		tx = now
		if j.dead(now, tx, rx) {
			died = now
			break
		}
	}
	if died == 0 {
		t.Fatal("после пробуждения тишина при отправке так и не признана")
	}
	// Отсчёт с пробуждения: 2000 мс до дремоты + то, что после.
	if after := died - (t0 + 1900 + 300_000); after > link.DeadMS {
		t.Errorf("после пробуждения мёртвым признано через %d мс, порог %d", after, link.DeadMS)
	}
	// Ответ хаба обнуляет всё накопленное.
	rx = now
	if j.dead(now+200, now+200, rx) {
		t.Error("сразу после ответа хаба путь мёртв")
	}
}

// ---- кадры, которым в туннеле некуда идти ----------------------------------------------------

// ip6Pkt — пакет IPv6 длиной n (минимум — заголовок в сорок байт).
func ip6Pkt(n int) []byte {
	p := make([]byte, n)
	p[0] = 0x60
	p[4], p[5] = byte((n-40)>>8), byte(n-40)
	p[6] = 58 // ICMPv6: ровно то, чем Android проверяет связь
	p[7] = 255
	return p
}

// TestПотокНеВезётНеIPv4: IPv6 и мусор из устройства не уходят к хабу и в потери не пишутся.
//
// Отброс стоял только в outbound (поддельный TCP), а на телефоне клиент работает потоком: IPv6,
// которым Android постоянно проверяет связь, уезжал к хабу, съедал место в записи и сходил за
// активную отправку. Счёт — отдельный от потерь, как и обещано у поля noV6: это не потеря пути.
func TestПотокНеВезётНеIPv4(t *testing.T) {
	t.Parallel()
	h := newStubHub(t)
	c := standStreamClient(t, h)
	dev := &memDev{}
	done, _ := runStream(t, c, dev)

	dev.push(ip6Pkt(80))
	dev.push([]byte{0x45, 0, 0, 10, 0, 0, 0, 0, 64, 17}) // короче заголовка IPv4
	dev.push(ip4Pkt(100))
	deadline := time.Now().Add(3 * time.Second)
	for {
		v4, _ := h.ipKinds()
		if v4 >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ok, err := alive(done, 300*time.Millisecond); !ok {
		t.Fatalf("сессия оборвалась: %v", err)
	}
	v4, other := h.ipKinds()
	if v4 != 1 {
		t.Errorf("до хаба дошло кадров IPv4: %d, ждали 1", v4)
	}
	if other != 0 {
		t.Errorf("до хаба дошло кадров не IPv4: %d — в потоке их никто не отбрасывает", other)
	}
	if n := c.noV6.Load(); n != 1 {
		t.Errorf("кадров IPv6 сосчитано %d, ждали 1", n)
	}
	if n := c.noIP.Load(); n != 1 {
		t.Errorf("кадров не IP сосчитано %d, ждали 1: короткий кадр — не IPv6", n)
	}
	if n := c.stats.dropped.Load(); n != 0 {
		t.Errorf("в потери записано %d: отброшенный не-IPv4 — не потеря пути", n)
	}
}

// TestКадрыНеIPv4СчитаютсяПоРоду: одна проверка на оба транспорта, и каждый род — в свой счётчик.
//
// Короткий кадр и кадр с чужой версией прежде назывались в журнале «IPv6», а все вместе ложились
// ещё и в потери — хотя поле noV6 обещало обратное.
func TestКадрыНеIPv4СчитаютсяПоРоду(t *testing.T) {
	var log []string
	c := &Client{opt: Options{Logf: func(f string, a ...any) {
		log = append(log, fmt.Sprintf(f, a...))
	}}}
	cases := []struct {
		name string
		f    []byte
		ok   bool
	}{
		{"IPv4", ip4Pkt(60), true},
		{"IPv4 ровно заголовок", ip4Pkt(20), true},
		{"IPv6", ip6Pkt(40), false},
		{"IPv4 короче заголовка", ip4Pkt(60)[:19], false},
		{"IPv6 короче заголовка", ip6Pkt(60)[:39], false},
		{"версия 5", append([]byte{0x55}, make([]byte, 59)...), false},
		{"пустой", nil, false},
	}
	for _, k := range cases {
		if got := c.tunnelable(k.f); got != k.ok {
			t.Errorf("%s: tunnelable = %v, ждали %v", k.name, got, k.ok)
		}
	}
	if n := c.noV6.Load(); n != 1 {
		t.Errorf("IPv6 сосчитано %d, ждали 1", n)
	}
	if n := c.noIP.Load(); n != 4 {
		t.Errorf("не IP сосчитано %d, ждали 4", n)
	}
	if n := c.stats.dropped.Load(); n != 0 {
		t.Errorf("в потери записано %d, ждали 0", n)
	}
	// Журнал: по одной строке на род (дальше — раз в минуту), и IPv6 назван только IPv6.
	if len(log) != 2 {
		t.Fatalf("строк журнала %d, ждали 2: %q", len(log), log)
	}
	if !strings.Contains(log[0], "IPv6") || strings.Contains(log[1], "IPv6 в туннель") {
		t.Errorf("журнал путает рода: %q", log)
	}
}
