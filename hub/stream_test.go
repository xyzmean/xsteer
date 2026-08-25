package hub

// Стенд режима потока: настоящий слушающий сокет ядра вместо поддельного TCP. Соединение здесь —
// пара net.Pipe, а не петля: streamConn от свойств транспорта не зависит (кроме SetNoDelay, который
// на паре просто не выполняется), а пара не занимает портов и не зависит от таймингов ядра.

import (
	"context"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/wire"
)

// streamAnswer прогоняет один Hello через streamConn и возвращает то, что хаб ответил.
func streamAnswer(t *testing.T, h *Hub, hello []byte) []byte {
	t.Helper()
	srv, cli := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); h.streamConn(context.Background(), srv) }()
	_ = cli.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := cli.Write(hello); err != nil {
		t.Fatalf("Hello не ушёл: %v", err)
	}
	buf := make([]byte, 64)
	n, _ := cli.Read(buf)
	_ = cli.Close()
	<-done
	return buf[:n]
}

// ---- находка: в режиме потока повтор msg1 отвечал молчанием -------------------

// TestПотокОтвечаетНаПовторТемЖе: в режиме потока ответ на воспроизведённый msg1 обязан совпадать
// с ответом любому другому неопознанному.
//
// В streamConn развилок «не наш» четыре: не похоже на TLS, рукопожатие не разобралось, нет такого
// пира, повтор msg1. Три первые пишут фатальное оповещение и считают постороннего, четвёртая
// закрывала соединение молча и не считала никого. Разный ответ на два разных «не наш» — это ровно
// то, что ищет активное зондирование: молчание вместо оповещения сообщает прибору, что записанный
// им Hello подобран ПРАВИЛЬНО и принадлежит описанному пиру. На половине поддельного TCP эта же
// ветка уже приведена к общей дорожке, а половина потока осталась со старым поведением.
func TestПотокОтвечаетНаПовторТемЖе(t *testing.T) {
	st := newStand(t)
	h := st.h

	// Эталон: посторонний, чьё рукопожатие не разобралось вовсе.
	want := streamAnswer(t, h, tlsRecord(900))
	if len(want) == 0 {
		t.Fatal("посторонний не получил ответа — сравнивать нечего")
	}
	strangers := h.stats.strangers.Load()

	// Повтор: настоящий msg1 настоящего пира, но метка времени старее уже виденной.
	cPriv, _ := standKeypair(t, 1)
	_, hPub := standKeypair(t, 2)
	h.commitStamp(0, uint64(time.Now().Unix())+3600)
	cli := &noise.HS{}
	hello, err := cli.ClientHello(cPriv, hPub, "www.microsoft.com", wire.MTUDefault, 0, false, true,
		rand.New(rand.NewSource(23)))
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}

	got := streamAnswer(t, h, hello)
	if len(got) == 0 {
		t.Fatal("на повтор msg1 хаб потоком не ответил ничем: молчание отличимо от ответа прочим " +
			"неопознанным и говорит прибору, что Hello подобран правильно")
	}
	if string(got) != string(want) {
		t.Errorf("на повтор ответ %x, на постороннего %x — ответы обязаны совпадать", got, want)
	}
	if h.stats.strangers.Load() != strangers+1 {
		t.Errorf("постороннних сосчитано %d, было %d — повтор в счётчик не попал",
			h.stats.strangers.Load(), strangers)
	}
}

// TestПотокОтвечаетНеопознанному — контроль: три прочие развилки отвечают и считают. Без него
// «ответы совпали» могло бы означать, что стенд не отвечает нигде.
func TestПотокОтвечаетНеопознанному(t *testing.T) {
	st := newStand(t)
	for _, c := range []struct {
		name  string
		hello []byte
	}{
		{"не похоже на TLS", []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")},
		{"рукопожатие не разобралось", tlsRecord(900)},
	} {
		base := st.h.stats.strangers.Load()
		got := streamAnswer(t, st.h, c.hello)
		if string(got) != string(noise.Alert()) {
			t.Errorf("%s: ответ %x, ждали фатальное оповещение %x", c.name, got, noise.Alert())
		}
		if st.h.stats.strangers.Load() != base+1 {
			t.Errorf("%s: посторонний не сосчитан", c.name)
		}
	}
}
