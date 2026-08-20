package client

// Стенд предела MTU у клиента: ни туннеля, ни root, ни сети.
//
// ЗАЧЕМ ИМЕННО ТАКОЙ. Поднять настоящий туннель в тесте нельзя — нужен /dev/net/tun, права на
// маршруты и живой хаб на другом конце, — а самая дорогая ошибка на этом пути не в подъёме, а в
// АРИФМЕТИКЕ РАЗМЕРОВ: рабочий MTU приходит от чужого устройства, из него считается предельный
// сегмент, а под продолжение разрезанной записи заведён буфер, посчитанный другим числом. Разойтись
// они могут молча, и снаружи это выглядит как «мелкие пакеты ходят, крупные пропадают» — худший
// класс отказов в диагностике. Ровно это и вышло в хабе (I-089).
//
// Поэтому стенд проверяет ЧИСЛА на настоящем пути отправки: поддельное соединение TCP в StateEst
// поверх сокета, которого нет, настоящие ключи из настоящего рукопожатия Noise IK и настоящий
// link.SendRecord. Устройство TUN не открывается ни разу.

import (
	"encoding/binary"
	"io"
	"math/rand"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/xyzmean/xsteer/link"
	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/wire"
)

// fakeRaw — сырой сокет, которого нет: отправленные сегменты складываются в память.
type fakeRaw struct {
	sent [][]byte
}

func (r *fakeRaw) Send(seg []byte) error {
	r.sent = append(r.sent, append([]byte(nil), seg...))
	return nil
}
func (r *fakeRaw) Recv([]byte) (int, error)             { return 0, io.EOF }
func (r *fakeRaw) WaitRead(time.Duration) (bool, error) { return false, nil }
func (r *fakeRaw) Local() [4]byte                       { return [4]byte{198, 51, 100, 1} }
func (r *fakeRaw) Close() error                         { return nil }

const (
	standListen = uint16(443)
	standSPort  = uint16(41000)
	standISN    = uint32(0x10000000)
)

// segPkt собирает пакет так, как он приходит из сырого сокета: заголовок IP плюс сегмент.
func segPkt(seq uint32, flags byte) []byte {
	src := [4]byte{203, 0, 113, 9}
	dst := [4]byte{198, 51, 100, 1}
	tcp := make([]byte, 60)
	opts := link.OptNone
	if flags&link.SYN != 0 {
		opts = link.OptScale
	}
	n := link.BuildSeg(tcp, src, dst, standSPort, standListen, seq, 1, flags, opts, nil)
	pkt := make([]byte, 20+n)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	pkt[9] = 6
	copy(pkt[12:16], src[:])
	copy(pkt[16:20], dst[:])
	copy(pkt[20:], tcp[:n])
	return pkt
}

// standConn — поддельное соединение TCP в StateEst без единого сокета.
//
// Через Accept, а не через Open: Open открыл бы настоящий сырой сокет (нужны права), а для арифметики
// размеров направление соединения не значит ничего — резать запись на сегменты умеет один и тот же
// код на обоих концах.
func standConn(t *testing.T) (*link.Conn, *fakeRaw) {
	t.Helper()
	raw := &fakeRaw{}
	syn, ok := link.ParseSeg(segPkt(standISN, link.SYN))
	if !ok {
		t.Fatal("свой же SYN не разобрался")
	}
	conn, err := link.Accept(raw, &syn, standListen, 0x20000000)
	if err != nil {
		t.Fatalf("link.Accept: %v", err)
	}
	ack, ok := link.ParseSeg(segPkt(standISN+1, link.ACK))
	if !ok {
		t.Fatal("свой же ACK не разобрался")
	}
	if _, err := conn.OnSeg(&ack); err != nil {
		t.Fatalf("OnSeg(ACK): %v", err)
	}
	if conn.State() != link.StateEst {
		t.Fatalf("соединение не поднялось: состояние %d", conn.State())
	}
	return conn, raw
}

// standKeys — ключи на отправку из настоящего рукопожатия. Подделать их нечем: Seal зовётся по
// настоящему пути, и запись обязана быть зашифрована так же, как в бою.
func standKeys(t *testing.T) *noise.Keys {
	t.Helper()
	var cPriv, hPriv [32]byte
	r := rand.New(rand.NewSource(5))
	r.Read(cPriv[:])
	r.Read(hPriv[:])
	p, err := curve25519.X25519(hPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var hPub [32]byte
	copy(hPub[:], p)

	cli, hub := &noise.HS{}, &noise.HS{}
	hello, err := cli.ClientHello(cPriv, hPub, "www.microsoft.com", wire.MTUDefault, 0, false, true,
		rand.New(rand.NewSource(6)))
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.ServerRead(hPriv, hello, rand.New(rand.NewSource(7))); err != nil {
		t.Fatal(err)
	}
	resp, _, _, err := hub.ServerWrite(wire.MTUDefault)
	if err != nil {
		t.Fatal(err)
	}
	tx, _, _, err := cli.ClientFinish(resp)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

// TestMTUЧужогоУстройстваЗажатПотолком: то же, что I-089 в хабе, только у клиента.
//
// Когда устройством владеет кто-то другой (служба системы, графический клиент), рабочий MTU берётся
// у него как есть: было предупреждение в журнал, но не было ЗАЖАТИЯ. Дальше по этому числу считается
// предельный сегмент (mtu + накладные - 40), а буфер продолжения разрезанной записи заведён своим
// числом — и при MTU устройства 1480 и выше КАЖДАЯ разрезаемая запись отваливалась в «мал буфер под
// продолжение записи» и уходила в счётчик отброшенных. Мелкое ходит, крупное молча пропадает.
//
// Число 1480 берётся не с потолка: это ровно то, что человек ставит устройству, думая про Ethernet
// минус что-нибудь, — и оно на 41 байт больше нашего предела, потому что наши накладные 61, а не 20.
func TestMTUЧужогоУстройстваЗажатПотолком(t *testing.T) {
	c := &Client{opt: Options{Logf: func(f string, a ...any) { t.Logf("клиент: "+f, a...) }}}

	for _, got := range []int{wire.MTUFloor, 1400, wire.MTUDefault, 1480, wire.LinkMax, 9000} {
		mtu := c.devMTU("xstest0", got)
		if mtu > wire.MTUDefault {
			t.Errorf("MTU устройства %d взят как есть: в работе %d, ждали не больше %d",
				got, mtu, wire.MTUDefault)
		}
		// Законное значение зажимать нельзя: узкий путь на то и узкий.
		if got <= wire.MTUDefault && mtu != got {
			t.Errorf("законный MTU устройства %d изменён на %d", got, mtu)
		}

		// И главное: с этим числом разрезаемая запись обязана УЕХАТЬ, а не попасть в счётчик
		// отброшенных. Проверяется настоящей отправкой, а не сравнением чисел между собой:
		// требование к размеру буфера живёт в link.SendRecord, и пересказывать его здесь значило бы
		// проверять пересказ.
		conn, raw := standConn(t)
		s := &sess{conn: conn, tx: standKeys(t), batchMax: 2}
		row := make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag)
		scratch := make([]byte, contLen)
		// Два кадра предельного размера: запись из них больше любого сегмента, то есть режется
		// всегда — без разрезания буфер продолжения не трогается вовсе, и проверка стала бы пустой.
		frames := [][]byte{make([]byte, 1400), make([]byte, 1400)}
		before := len(raw.sent)
		if err := c.sendFrames(s, row, scratch, frames, mtu); err != nil {
			t.Errorf("MTU устройства %d (в работе %d): разрезаемая запись не ушла: %v", got, mtu, err)
			continue
		}
		if n := len(raw.sent) - before; n < 2 {
			t.Errorf("MTU устройства %d: запись уехала %d сегментами — разрезания не было", got, n)
		}
	}
}
