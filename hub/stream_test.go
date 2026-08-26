package hub

// Стенд режима потока: настоящий слушающий сокет ядра вместо поддельного TCP. Соединение здесь —
// пара net.Pipe, а не петля: streamConn от свойств транспорта не зависит (кроме SetNoDelay, который
// на паре просто не выполняется), а пара не занимает портов и не зависит от таймингов ядра.

import (
	"context"
	"math/rand"
	"net"
	"runtime"
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

// ---- находка I-133: побудка чтения ждала отмены ХАБА, а не соединения ----------

// streamUpDown проводит полное рукопожатие пира по паре net.Pipe, затем закрывает свою половину и
// дожидается возврата streamConn. То есть проходит ровно тот путь, на котором соединение доживает
// до конца рукопожатия — единственный, где заводится горутина побудки чтения.
func streamUpDown(t *testing.T, h *Hub, ctx context.Context, seed int64) {
	t.Helper()
	srv, cli := net.Pipe()
	done := make(chan struct{})
	go func() { defer close(done); h.streamConn(ctx, srv) }()
	_ = cli.SetDeadline(time.Now().Add(5 * time.Second))

	cPriv, _ := standKeypair(t, 1)
	_, hPub := standKeypair(t, 2)
	hs := &noise.HS{}
	defer hs.Wipe()
	hello, err := hs.ClientHello(cPriv, hPub, "www.microsoft.com", wire.MTUDefault, 0, false, true,
		rand.New(rand.NewSource(seed)))
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if _, err := cli.Write(hello); err != nil {
		t.Fatalf("Hello не ушёл: %v", err)
	}
	// Ответ хаба уходит одной записью (st.WriteRaw), поэтому одного чтения достаточно.
	buf := make([]byte, 4096)
	n, err := cli.Read(buf)
	if err != nil {
		t.Fatalf("ответ хаба не прочитан: %v", err)
	}
	tx, _, consumed, err := hs.ClientFinish(buf[:n])
	if err != nil {
		t.Fatalf("ClientFinish: %v (ответ %d байт)", err, n)
	}
	if consumed != n {
		t.Fatalf("пир израсходовал %d из %d байт ответа", consumed, n)
	}
	fin, err := hs.ClientConfirm(tx)
	if err != nil {
		t.Fatalf("ClientConfirm: %v", err)
	}
	if _, err := cli.Write(fin); err != nil {
		t.Fatalf("подтверждение не ушло: %v", err)
	}
	// Соединение поднялось. Обрыв со стороны пира — самый частый способ его конца: чтение записи
	// в streamConn получает ошибку и обработчик возвращается.
	_ = cli.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("streamConn не вернулся после обрыва соединения")
	}
}

// TestПотокНеОставляетГорутинуПослеОбрыва: у горутины, которая будит чтение закрытием сокета, срок
// жизни обязан быть срок жизни СОЕДИНЕНИЯ, а не хаба.
//
// У потока нет опроса с таймаутом, поэтому прервать блокирующее ReadRecord можно только закрытием
// сокета извне — этим и занимается отдельная горутина. Ждать в ней отмены контекста ХАБА значит
// оставлять её после каждого поднявшегося соединения: дескриптор закроет defer, а стек горутины и
// объект соединения останутся достижимыми до остановки процесса. Пир на мобильной сети,
// пересоединяющийся раз в полминуты, набирает так почти три тысячи горутин в сутки. В парной
// половине у пира (client/stream.go) то же место сделано производным контекстом с defer stop().
func TestПотокНеОставляетГорутинуПослеОбрыва(t *testing.T) {
	st := newStand(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Прогрев: первое соединение поднимает ленивые внутренности рантайма и net.Pipe, и их горутины
	// не должны попасть в замер как утечка.
	streamUpDown(t, st.h, ctx, 41)
	time.Sleep(200 * time.Millisecond) // дать уйти горутинам прогрева
	base := runtime.NumGoroutine()

	const conns = 8
	for i := 0; i < conns; i++ {
		streamUpDown(t, st.h, ctx, int64(100+i))
	}
	// Контекст хаба ЖИВ — в этом вся находка: соединений нет, а горутины, ждущие его отмены, есть.
	left := waitGoroutines(base, 3*time.Second)
	if left > base {
		t.Errorf("после %d поднявшихся и оборванных соединений горутин %d, до них %d: побудка чтения "+
			"ждёт отмены хаба, а не соединения — каждое переподключение оставляет горутину до конца "+
			"жизни процесса", conns, left, base)
	}
}

// waitGoroutines ждёт, пока число горутин опустится до want, и возвращает то, что получилось.
// Опрос нужен потому, что возврат обработчика и уход его горутин не одновременны.
func waitGoroutines(want int, limit time.Duration) int {
	deadline := time.Now().Add(limit)
	for {
		n := runtime.NumGoroutine()
		if n <= want || time.Now().After(deadline) {
			return n
		}
		time.Sleep(10 * time.Millisecond)
	}
}
