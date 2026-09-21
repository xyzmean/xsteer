package client

// Стенд сброса живого соединения: RST с ожидаемым номером в StateEst обязан закончить сессию.
//
// ЗАЧЕМ. OnSeg на законный RST переводит соединение в StateClosed и возвращает ErrDead — и на этом
// у клиента всё останавливалось. Горутина приёма записывала ошибку в журнал и выходила из ЗАХОДА,
// а не из соединения; отправка получала «соединение не установлено» — не ErrDead и не ErrPathGone,
// то есть молча считала кадры отброшенными; ход времени звал Tick, который для любого состояния
// кроме SynSent и Est возвращает nil. Никто не отменял контекст сессии, и worker не поднимал
// соединение заново: после штатного перезапуска хаба (его ядро отвечает RST на первый же наш
// сегмент, пока правило против RST снято) туннель стоял мёртвым до смены сети или перезапуска
// клиента. Половина на C в том же месте зовёт session_down (xsclient.c, ветка what < 0).
//
// Стенд — без сокета и без устройства: соединение в StateEst поверх памяти (как в mtu_test.go),
// сырой сокет подсовывает один сегмент RST с номером, которого ждёт соединение, и проверяется
// ровно одно: inbound ВОЗВРАЩАЕТСЯ. Пока он не возвращался, у сессии не было повода закончиться.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xyzmean/xsteer/link"
	"github.com/xyzmean/xsteer/tun"
)

// feedRaw — сырой сокет, у которого принятое подсовывается заранее: очередь пакетов, по одному на
// Recv. Пустая очередь ведёт себя как настоящий сокет без данных — WaitRead выжидает срок и
// отвечает «нет», Recv отдаёт ErrAgain.
type feedRaw struct {
	fakeRaw
	mu   sync.Mutex
	pkts [][]byte
}

func (r *feedRaw) WaitRead(d time.Duration) (bool, error) {
	r.mu.Lock()
	n := len(r.pkts)
	r.mu.Unlock()
	if n > 0 {
		return true, nil
	}
	time.Sleep(d)
	return false, nil
}

func (r *feedRaw) Recv(buf []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pkts) == 0 {
		return 0, link.ErrAgain
	}
	p := r.pkts[0]
	r.pkts = r.pkts[1:]
	return copy(buf, p), nil
}

// nopDev — устройство, которого нет: приёму оно нужно только ради Write и Flush.
type nopDev struct{}

func (nopDev) Read(p []byte) (int, error)           { return 0, tun.ErrAgain }
func (nopDev) WaitRead(time.Duration) (bool, error) { return false, nil }
func (nopDev) Write(p []byte) (int, error)          { return len(p), nil }
func (nopDev) Flush() error                         { return nil }
func (nopDev) Name() string                         { return "xstest0" }
func (nopDev) SetMTU(int) error                     { return nil }
func (nopDev) Close() error                         { return nil }

func TestRSTНаЖивомСоединенииЗаканчиваетПриём(t *testing.T) {
	var logMu sync.Mutex
	var logs []string
	c := &Client{opt: Options{Logf: func(f string, a ...any) {
		logMu.Lock()
		logs = append(logs, fmt.Sprintf(f, a...))
		logMu.Unlock()
	}}}
	c.hub.str = "203.0.113.9:443"

	raw := &feedRaw{}
	conn := standConnOn(t, raw)
	// Номер RST — ровно тот, которого соединение ждёт (c.ack после рукопожатия): с любым другим
	// OnSeg его отвергнет, и это уже проверено в link (TestOnSegRSTNeedsExpectedSeq).
	raw.pkts = append(raw.pkts, segPkt(standISN+1, link.RST))
	s := &sess{conn: conn, packs: make(chan int, 4), batchMax: 2}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.inbound(ctx, 0, s, nopDev{}, "xstest0")
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("после RST с ожидаемым номером приём не вернулся за две секунды — сессия не заканчивается")
	}
	if st := conn.State(); st != link.StateClosed {
		t.Fatalf("состояние соединения после RST: %d, ждали StateClosed", st)
	}
	logMu.Lock()
	defer logMu.Unlock()
	for _, l := range logs {
		if strings.Contains(l, "RST") {
			return
		}
	}
	t.Fatalf("в журнале нет строки про RST, есть: %q", logs)
}
