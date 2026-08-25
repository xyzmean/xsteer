package hub

// Стенд дорожки неопознанного: настоящее поддельное соединение к хабу и НАСТОЯЩИЙ слушающий сокет
// на петле в роли сайта-прикрытия. Сырой сокет подменён памятью (fakeRaw из worker_test.go), root
// не нужен.
//
// Зачем именно так. Вся ценность режима proxy в том, что прибор видит подлинный ответ подлинного
// сервера. Проверить это можно только на настоящем сокете: заглушка «сайта-прикрытия» отвечала бы
// тем, что мы сами в неё положили, и не заметила бы главного — что прикрытию уходит обрубок Hello
// вместо всего Hello, потому что обрубок она бы тоже приняла.

import (
	"encoding/binary"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/xyzmean/xsteer/link"
	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/wire"
)

// ---- посторонний на том же воркере -------------------------------------------

// probe — вторая сессия поддельного TCP: тот, кто постучался с другого адреса и своим не окажется.
type probe struct {
	st    *stand
	src   [4]byte
	sport uint16
	seq   uint32
	s     *session
	k     skey
}

func newProbe(t *testing.T, st *stand, n byte) *probe {
	t.Helper()
	p := &probe{
		st: st, src: [4]byte{198, 18, 0, n}, sport: standSPort + 100 + uint16(n),
		seq: 0x30000000 + uint32(n)<<16,
	}
	syn := segPkt(p.src, p.sport, p.seq, link.SYN, nil)
	parsed, ok := link.ParseSeg(syn)
	if !ok {
		t.Fatal("свой же SYN не разобрался")
	}
	conn, err := link.Accept(st.raw, &parsed, standListen, 0x50000000+uint32(n)<<16)
	if err != nil {
		t.Fatalf("link.Accept: %v", err)
	}
	p.k = skey{addr: p.src, port: p.sport}
	p.s = &session{conn: conn, phase: phSyn, peer: -1, connID: -1}
	st.w.sess[p.k] = p.s
	p.seq++ // SYN занял один номер
	p.feed(link.ACK, nil)
	return p
}

func (p *probe) feed(flags byte, payload []byte) {
	p.st.t.Helper()
	seg, ok := link.ParseSeg(segPkt(p.src, p.sport, p.seq, flags, payload))
	if !ok {
		p.st.t.Fatal("сегмент не разобрался")
	}
	p.seq += uint32(len(payload))
	p.st.w.onSeg(&seg)
}

// tlsRecord — запись, похожая на ClientHello по заголовку и не являющаяся нашим рукопожатием.
// Именно так выглядит зондирование: настоящий прибор присылает настоящий Hello чужого стека.
func tlsRecord(body int) []byte {
	rec := make([]byte, 5+body)
	rec[0], rec[1], rec[2] = 0x16, 0x03, 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(body))
	for i := 5; i < len(rec); i++ {
		rec[i] = byte(i * 7)
	}
	return rec
}

// decoySite — слушающий сокет в роли сайта-прикрытия. Возвращает адрес и канал, в который уйдёт
// всё, что прикрытие успело прочитать до тишины.
func decoySite(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("прикрытие не поднялось: %v", err)
	}
	got := make(chan []byte, 1)
	go func() {
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		var all []byte
		buf := make([]byte, 4096)
		for {
			// Короткий срок: проверяется то, что уже прислано, а не то, что придёт когда-нибудь.
			_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, err := c.Read(buf)
			all = append(all, buf[:n]...)
			if err != nil {
				break
			}
		}
		got <- all
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), got
}

// ---- находка: прикрытию уходил обрубок Hello ---------------------------------

// TestПрикрытиюУходитВсёПрисланное: Hello из двух сегментов доезжает до сайта-прикрытия целиком.
//
// Браузерный ClientHello больше одного сегмента (у современного Chrome около 1700 байт из-за
// постквантового ключа), и хаб честно собирает его в session.hsBuf. Но handshake() обнулял hsBuf
// ДО развилки «наш или нет», а дорожка неопознанного берёт присланное именно оттуда — и получала
// пусто, откатываясь на последний сегмент. То есть прикрытие видело хвост записи TLS без её
// начала: настоящий сервер на такое отвечает не так, как ответил бы прибору напрямую, а с
// --decoy-sni имя из обрубка не разбирается вовсе и прибор получает сертификат чужого сайта.
// Ровно этот порядок описан в реализации на C (xshub.c, hs_step): «накопленное НЕ ОЧИЩАЕТСЯ до
// этой развилки нарочно».
func TestПрикрытиюУходитВсёПрисланное(t *testing.T) {
	st := newStand(t)
	dest, got := decoySite(t)
	st.h.opt.Decoy = DecoyMode{Mode: "proxy", Dest: dest, Timeout: time.Second}

	hello := tlsRecord(900)
	p := newProbe(t, st, 1)
	// Два сегмента: первый неполон, и разобрать его нельзя — именно поэтому накопленное и есть
	// единственный источник целого Hello.
	p.feed(link.PSH|link.ACK, hello[:400])
	p.feed(link.PSH|link.ACK, hello[400:])

	if p.s.phase != phProxy {
		t.Fatalf("фаза %d, ждали phProxy — дорожка проксирования не началась", p.s.phase)
	}
	seen := <-got
	if len(seen) != len(hello) {
		t.Errorf("прикрытие получило %d байт из %d — оно отвечает на обрубок Hello",
			len(seen), len(hello))
	}
	if len(seen) == len(hello) && string(seen) != string(hello) {
		t.Error("прикрытие получило не то, что прислал прибор")
	}
}

// TestПрикрытиеПолучаетОдносегментныйHello — контроль к проверке выше: на Hello, влезшем в один
// сегмент, дорожка работала и до правки. Без этого контроля «не дошло» могло бы означать, что
// стенд не поднялся вовсе.
func TestПрикрытиеПолучаетОдносегментныйHello(t *testing.T) {
	st := newStand(t)
	dest, got := decoySite(t)
	st.h.opt.Decoy = DecoyMode{Mode: "proxy", Dest: dest, Timeout: time.Second}

	hello := tlsRecord(200)
	p := newProbe(t, st, 2)
	p.feed(link.PSH|link.ACK, hello)

	if p.s.phase != phProxy {
		t.Fatalf("фаза %d, ждали phProxy", p.s.phase)
	}
	if seen := <-got; string(seen) != string(hello) {
		t.Errorf("прикрытие получило %d байт из %d", len(seen), len(hello))
	}
}

// ---- находка: повтор msg1 отвечал молчанием при любой настройке ---------------

// TestПовторMsg1ОтвечаетТемЖе: на воспроизведённый msg1 хаб отвечает так же, как любому другому
// неопознанному.
//
// Ветка защиты от повтора закрывала сессию молча, то есть отвечала «silent» независимо от
// настройки Decoy. Разный ответ на два разных «не наш» — это ровно то, что ищет активное
// зондирование: молчание вместо оповещения сообщает прибору, что записанный им Hello подобран
// ПРАВИЛЬНО и принадлежит описанному пиру. Реализация на C эту ветку уже проводит через общую
// дорожку (xshub.c, «прежде эта ветка молча закрывала сессию»).
func TestПовторMsg1ОтвечаетТемЖе(t *testing.T) {
	st := newStand(t)
	// Настройка по умолчанию — фатальное оповещение. Проверять её удобнее прочих: RST уходит
	// отдельным отправителем (worker.tx0), которого в стенде нет, а оповещение идёт тем же
	// поддельным соединением, что и всё остальное.
	st.h.opt.Decoy = DecoyMode{}

	// Ответ на постороннего: эталон, с которым сравнивается ответ на повтор.
	base := len(st.raw.sent)
	garbage := newProbe(t, st, 3)
	garbage.feed(link.PSH|link.ACK, tlsRecord(120))
	want := st.raw.payloadsSince(base)
	if len(want) == 0 {
		t.Fatal("посторонний не получил ответа — сравнивать нечего")
	}

	// Повтор: настоящий msg1 настоящего пира, но метка времени старее уже виденной.
	cPriv, _ := standKeypair(t, 1)
	_, hPub := standKeypair(t, 2)
	st.h.commitStamp(0, uint64(time.Now().Unix())+3600)
	cli := &noise.HS{}
	hello, err := cli.ClientHello(cPriv, hPub, "www.microsoft.com", wire.MTUDefault, 0, false, true,
		rand.New(rand.NewSource(77)))
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}

	base = len(st.raw.sent)
	replay := newProbe(t, st, 4)
	replay.feed(link.PSH|link.ACK, hello)
	got := st.raw.payloadsSince(base)
	if len(got) == 0 {
		t.Fatal("на повтор msg1 хаб не ответил ничем: молчание отличимо от ответа прочим " +
			"неопознанным и говорит прибору, что Hello подобран правильно")
	}
	if string(got) != string(want) {
		t.Errorf("на повтор ответ %x, на постороннего %x — ответы обязаны совпадать", got, want)
	}
}
