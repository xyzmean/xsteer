package xsteer

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xyzmean/xsteer/tun"
)

// sinkRec — получатель пакетов, запоминающий всё, что ему отдали.
type sinkRec struct {
	mu      sync.Mutex
	pkts    [][]byte
	v6      []bool
	flushes int
}

func (s *sinkRec) WritePacket(p []byte, ipv6 bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := make([]byte, len(p))
	copy(b, p)
	s.pkts = append(s.pkts, b)
	s.v6 = append(s.v6, ipv6)
}

func (s *sinkRec) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushes++
}

func (s *sinkRec) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pkts)
}

func v4pkt(n int) []byte {
	p := make([]byte, n)
	p[0] = 0x45
	return p
}

// Пустая очередь обязана отвечать ErrAgain, а не нулём и не отказом: на нуле путь данных молча
// закрывает всплеск, на отказе — уходит из соединения.
func TestReadEmptyIsErrAgain(t *testing.T) {
	d := NewDevice("t", &sinkRec{}, 1400)
	buf := make([]byte, 1500)
	n, err := d.Read(buf)
	if n != 0 || !errors.Is(err, tun.ErrAgain) {
		t.Fatalf("пусто дало (%d, %v), ждали (0, ErrAgain)", n, err)
	}
}

func TestInjectThenRead(t *testing.T) {
	d := NewDevice("t", &sinkRec{}, 1400)
	in := v4pkt(60)
	in[59] = 0xAB
	d.Inject(in)
	buf := make([]byte, 1500)
	n, err := d.Read(buf)
	if err != nil || n != 60 || buf[59] != 0xAB {
		t.Fatalf("прочитано (%d, %v), последний байт %#x", n, err, buf[59])
	}
}

// ГЛАВНАЯ проверка чтения: пакет, не влезший в буфер, выбрасывается ЦЕЛИКОМ. Отдать начало
// значило бы отправить в туннель обрубок с настоящей длиной в заголовке IP — получатель молча
// выбросил бы его, и снаружи это выглядело бы как «мелкое ходит, крупное пропадает».
func TestReadDropsOversizeWhole(t *testing.T) {
	d := NewDevice("t", &sinkRec{}, 1400)
	d.Inject(v4pkt(2000))
	small := v4pkt(40)
	small[39] = 0x7E
	d.Inject(small)

	buf := make([]byte, 1439)
	n, err := d.Read(buf)
	if err != nil {
		t.Fatalf("после крупного чтение дало отказ: %v", err)
	}
	if n != 40 || buf[39] != 0x7E {
		t.Fatalf("вместо следующего пакета прочитано %d байт (ждали 40 и байт 0x7E)", n)
	}
	if d.Oversize() != 1 {
		t.Fatalf("счётчик крупных %d, ждали 1", d.Oversize())
	}
	if d.Dropped() != 0 {
		t.Fatalf("крупный пакет посчитан как перегрузка: dropped=%d", d.Dropped())
	}
}

// Переполнение очереди теряет и считает, но не блокирует: ждать здесь значило бы задержать
// чтение у системы, то есть сделать хуже.
func TestInjectOverflowCounts(t *testing.T) {
	d := NewDevice("t", &sinkRec{}, 1400)
	for i := 0; i < queueLen+17; i++ {
		d.Inject(v4pkt(40))
	}
	if d.Dropped() != 17 {
		t.Fatalf("потеряно %d, ждали 17", d.Dropped())
	}
}

// WaitRead обязан вернуть false БЕЗ ошибки по истечении срока: ошибку вызывающий считает
// смертельной и уходит из соединения.
func TestWaitReadTimeoutIsNotError(t *testing.T) {
	d := NewDevice("t", &sinkRec{}, 1400)
	start := time.Now()
	ok, err := d.WaitRead(50 * time.Millisecond)
	if err != nil {
		t.Fatalf("таймаут дал отказ: %v", err)
	}
	if ok {
		t.Fatal("на пустой очереди сказано, что есть что читать")
	}
	if el := time.Since(start); el < 40*time.Millisecond {
		t.Fatalf("вернулся через %v, то есть не ждал", el)
	}
}

// Пакет, положенный во время ожидания, обязан разбудить WaitRead — и остаться в очереди, потому
// что забирает его Read, а не WaitRead.
func TestWaitReadWakesAndKeepsPacket(t *testing.T) {
	d := NewDevice("t", &sinkRec{}, 1400)
	go func() {
		time.Sleep(20 * time.Millisecond)
		d.Inject(v4pkt(40))
	}()
	ok, err := d.WaitRead(2 * time.Second)
	if err != nil || !ok {
		t.Fatalf("WaitRead дал (%v, %v)", ok, err)
	}
	buf := make([]byte, 1500)
	if n, err := d.Read(buf); n != 40 || err != nil {
		t.Fatalf("после ожидания пакет не нашёлся: (%d, %v)", n, err)
	}
}

// Закрытое устройство отвечает «времени нет», а не отказом: уходить пути данных положено по
// отмене контекста.
func TestWaitReadAfterCloseIsNotError(t *testing.T) {
	d := NewDevice("t", &sinkRec{}, 1400)
	d.Close()
	ok, err := d.WaitRead(10 * time.Millisecond)
	if err != nil {
		t.Fatalf("закрытое устройство дало отказ: %v", err)
	}
	if ok {
		t.Fatal("закрытое устройство обещало пакеты")
	}
}

// Запись отдаёт пакет СРАЗУ, не дожидаясь Flush: входящий путь режима потока Flush не зовёт
// вообще, и накопленное пролежало бы там навсегда.
func TestWriteDeliversWithoutFlush(t *testing.T) {
	s := &sinkRec{}
	d := NewDevice("t", s, 1400)
	if _, err := d.Write(v4pkt(80)); err != nil {
		t.Fatalf("запись дала отказ: %v", err)
	}
	if s.count() != 1 {
		t.Fatalf("отдано %d пакетов до Flush, ждали 1", s.count())
	}
	if s.flushes != 0 {
		t.Fatal("Flush позвался сам собой")
	}
}

// Семейство выводится из версии в первом полубайте: writePackets требует его на каждый пакет, а
// в байтах пакета его нет.
func TestWritePicksFamily(t *testing.T) {
	s := &sinkRec{}
	d := NewDevice("t", s, 1400)
	v6 := make([]byte, 60)
	v6[0] = 0x60
	d.Write(v4pkt(40))
	d.Write(v6)
	if s.count() != 2 {
		t.Fatalf("отдано %d, ждали 2", s.count())
	}
	if s.v6[0] || !s.v6[1] {
		t.Fatalf("семейства определены неверно: %v", s.v6)
	}
}

// Не IP — отбрасывается, а не отдаётся системе под угаданной вывеской.
func TestWriteDropsNonIP(t *testing.T) {
	s := &sinkRec{}
	d := NewDevice("t", s, 1400)
	bad := make([]byte, 40)
	bad[0] = 0x00
	if n, err := d.Write(bad); n != 0 || err != nil {
		t.Fatalf("не-IP дал (%d, %v), ждали (0, nil)", n, err)
	}
	if s.count() != 0 {
		t.Fatal("не-IP уехал системе")
	}
	if d.Dropped() != 1 {
		t.Fatalf("не-IP не посчитан: dropped=%d", d.Dropped())
	}
}

// Запись в закрытое устройство — отказ: писать больше некуда, и путь данных посчитает это одним
// отброшенным пакетом.
func TestWriteAfterCloseFails(t *testing.T) {
	d := NewDevice("t", &sinkRec{}, 1400)
	d.Close()
	if _, err := d.Write(v4pkt(40)); !errors.Is(err, tun.ErrNoDevice) {
		t.Fatalf("закрытое устройство дало %v, ждали ErrNoDevice", err)
	}
}

// Предела размера на записи нет: пир с большим MTU законно присылает пакет крупнее нашего, и
// предел здесь — открытый текст записи, а не MTU туннеля.
func TestWriteHasNoMTULimit(t *testing.T) {
	s := &sinkRec{}
	d := NewDevice("t", s, 1400)
	big := v4pkt(4000)
	if n, err := d.Write(big); n != 4000 || err != nil {
		t.Fatalf("крупная запись дала (%d, %v)", n, err)
	}
	if s.count() != 1 {
		t.Fatal("крупный пакет не уехал")
	}
}

// Чтение и запись идут из РАЗНЫХ горутин по одному устройству: на этом держится путь данных.
func TestConcurrentReadWrite(t *testing.T) {
	s := &sinkRec{}
	d := NewDevice("t", s, 1400)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			d.Inject(v4pkt(60))
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 1439)
		for i := 0; i < 2000; i++ {
			d.Read(buf)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			d.Write(v4pkt(60))
		}
	}()
	wg.Wait()
}
