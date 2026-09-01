package hub

// Стенд режима потока: настоящий слушающий сокет ядра вместо поддельного TCP. Соединение здесь —
// пара net.Pipe, а не петля: streamConn от свойств транспорта не зависит (кроме SetNoDelay, который
// на паре просто не выполняется), а пара не занимает портов и не зависит от таймингов ядра.

import (
	"context"
	"math/rand"
	"net"
	"runtime"
	"sync"
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

// streamPeer — половина ПИРА на паре net.Pipe: поднятое соединение потока и всё, чем по нему можно
// посылать записи. Записи шифруются смещением потока, поэтому рукопожатие обязано идти через тот же
// объект wire.Stream (WriteRaw), а не напрямую в сокет: иначе смещения сторон разъедутся на длину
// рукопожатия и первая же запись данных не расшифруется.
type streamPeer struct {
	nc   net.Conn
	st   *wire.Stream
	tx   *noise.Keys
	row  []byte
	done chan struct{} // закрывается, когда streamConn вернулся
}

// streamPeerUp проводит полное рукопожатие пира и возвращает поднятое соединение. То есть проходит
// ровно тот путь, на котором соединение доживает до конца рукопожатия, — единственный, где хаб
// заводит горутину побудки чтения и сессию в peerSess.
func streamPeerUp(t *testing.T, h *Hub, ctx context.Context, seed int64) *streamPeer {
	t.Helper()
	srv, cli := net.Pipe()
	p := &streamPeer{nc: cli, st: wire.NewStream(cli), done: make(chan struct{}),
		row: make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag)}
	go func() { defer close(p.done); h.streamConn(ctx, srv) }()
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
	if err := p.st.WriteRaw(hello); err != nil {
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
	if err := p.st.WriteRaw(fin); err != nil {
		t.Fatalf("подтверждение не ушло: %v", err)
	}
	p.tx = tx
	// Срок на сокете пира снимается: дальше распоряжается сроками сам стенд.
	_ = cli.SetDeadline(time.Time{})
	return p
}

// send отправляет одну запись с нагрузкой n байт — так же, как это делает пир (client.streamSend).
// Нулевая длина и есть keepalive: пустоту хаб опознаёт как вид кадра.
func (p *streamPeer) send(n int) error {
	rec := p.row[wire.HdrRoom-wire.RecHdr : wire.HdrRoom]
	return p.st.WriteRecord(p.row, wire.RecHdr+n+wire.Tag, func(rel uint64) error {
		if err := wire.RecBuild(rec, n+wire.Tag); err != nil {
			return err
		}
		_, err := p.tx.Seal(p.row[wire.HdrRoom:wire.HdrRoom+n+wire.Tag], n, rec, rel)
		return err
	})
}

// closeWait рвёт соединение со стороны пира — самый частый способ его конца — и дожидается возврата
// обработчика.
func (p *streamPeer) closeWait(t *testing.T) {
	t.Helper()
	_ = p.nc.Close()
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		t.Fatal("streamConn не вернулся после обрыва соединения")
	}
}

func streamUpDown(t *testing.T, h *Hub, ctx context.Context, seed int64) {
	t.Helper()
	streamPeerUp(t, h, ctx, seed).closeWait(t)
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

// ---- находка I-132: сессию потока не обслуживает никто -------------------------

// TestПотокУмираетПоПростою: сессия потока обязана умирать по тому же простою, что и сессия
// поддельного TCP, и срок обязан ПЕРЕСТАВЛЯТЬСЯ на каждой записи.
//
// Обслуживание сессий (w.maintain) зовётся только из rxLoop, то есть с половины поддельного TCP;
// воркер, которого streamConn заводит под своё соединение, туда не попадает никогда. Значит для
// потока не выполняется ни уборка по IdleMS, ни что-либо ещё, а после рукопожатия срок снимался
// совсем — цикл чтения своего не ставил. Пир, пропавший молча (отображение NAT истекло, устройство
// уснуло, провод выдернут), не обнаруживался НИЧЕМ, кроме ядерного keepalive: 7200 с тишины плюс
// девять проб по 75 — около 2 ч 11 мин вместо 180 с у парной половины. Держались это время не
// только горутина и 80 КиБ буферов, но и значение MTU мёртвой сессии: retuneMTU берёт минимум по
// всем непустым слотам peerSess, поэтому пир с маленьким MTU зажимал MTU устройства ВСЕГО хаба два
// часа после того, как перестал существовать.
//
// Вторая половина проверки не менее важна первой: живой пир присылает пробу живости каждые две
// секунды, и срок, поставленный один раз на всё соединение, убивал бы живые сессии.
func TestПотокУмираетПоПростою(t *testing.T) {
	st := newStand(t)
	saved := streamIdle
	streamIdle = 250 * time.Millisecond // вместо трёх минут: стенд не должен их ждать
	defer func() { streamIdle = saved }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := streamPeerUp(t, st.h, ctx, 17)

	// Пир жив и молчит короткими промежутками. Суммарно 480 мс — почти вдвое дольше срока, то есть
	// без переставления соединение уже было бы закрыто.
	for i := 1; i <= 6; i++ {
		time.Sleep(80 * time.Millisecond)
		if err := p.send(0); err != nil {
			t.Fatalf("проба живости %d не ушла: %v — соединение закрыто раньше времени, срок не "+
				"переставляется на каждой записи", i, err)
		}
		select {
		case <-p.done:
			t.Fatalf("обработчик вернулся на %d-й пробе живости: срок поставлен один раз на всё "+
				"соединение, а живой пир молчит промежутками", i)
		default:
		}
	}

	// А теперь пир пропал молча: ни обрыва, ни FIN — так выглядит истёкшее отображение NAT.
	select {
	case <-p.done:
	case <-time.After(3 * time.Second):
		cancel()
		t.Error("сессия потока не умерла по простою: срока на чтение нет, и пропавший молча пир " +
			"держит слот peerSess, буферы и потолок MTU устройства до ядерного keepalive — около " +
			"2 ч 11 мин")
	}
}

// ---- слушатель потока: ошибка accept и предел одновременных ------------------
//
// Обе проверки идут через streamServe, а не через streamListen: слушателя подставляет стенд.
// Настоящим сокетом ни ошибку accept, ни исчерпание дескрипторов не воспроизвести — первое
// требует состояния ядра (кончились дескрипторы, соединение отвалилось между SYN и accept),
// второе заняло бы все дескрипторы процесса стенда.

// errListener — слушатель, который сначала отдаёт заданное число ошибок, потом соединения.
//
// Close ведёт себя как настоящий: после него Accept отвечает net.ErrClosed. Без этого стенд
// проверял бы выход по отмене на слушателе, который вечно ждёт, — то есть проверял бы свою
// заглушку, а не streamServe.
type errListener struct {
	errs   int           // сколько раз ответить ошибкой
	conns  chan net.Conn // что отдавать дальше
	fail   error
	closed chan struct{}
	once   sync.Once
}

func newErrListener(errs int, fail error) *errListener {
	return &errListener{errs: errs, fail: fail,
		conns: make(chan net.Conn, 8), closed: make(chan struct{})}
}

func (l *errListener) Accept() (net.Conn, error) {
	if l.errs > 0 {
		l.errs--
		return nil, l.fail
	}
	select {
	case nc := <-l.conns:
		return nc, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *errListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *errListener) Addr() net.Addr { return &net.TCPAddr{} }

// tempErr — ошибка того рода, который accept возвращает на временной беде.
type tempErr struct{}

func (tempErr) Error() string { return "слишком много открытых файлов" }

func TestПотокПереживаетОшибкуAccept(t *testing.T) {
	// Раньше любая ошибка accept возвращалась из streamListen наружу, то есть слушатель умирал
	// НАВСЕГДА: хаб при этом оставался жив, поддельный TCP работал, а половина потока молча
	// перестала принимать соединения. Ни в журнале, ни в состоянии этого не видно — пир просто
	// не может подключиться, и причина выглядит как проблема сети.
	h := newStand(t).h
	ln := newErrListener(3, tempErr{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	streamAcceptPause = time.Millisecond // стенду не ждать
	defer func() { streamAcceptPause = 20 * time.Millisecond }()

	done := make(chan error, 1)
	go func() { done <- h.streamServe(ctx, ln) }()

	// После трёх ошибок слушатель обязан принять соединение.
	srv, cli := net.Pipe()
	select {
	case ln.conns <- srv:
	case <-time.After(2 * time.Second):
		t.Fatal("слушатель не дошёл до приёма соединения после ошибок accept")
	}
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	// Соединение принято, если хаб на мусор ответил оповещением: значит streamConn его получил.
	if _, err := cli.Write([]byte("не рукопожатие вовсе, но записи хватит")); err != nil {
		t.Fatalf("запись в принятое соединение: %v", err)
	}
	buf := make([]byte, 8)
	if _, err := cli.Read(buf); err != nil {
		t.Fatalf("хаб не ответил на принятое соединение: %v", err)
	}
	cli.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("streamServe не вышла по отмене контекста")
	}
}

func TestПотокОтказываетСверхПредела(t *testing.T) {
	// Слушатель принимал без потолка: каждое НЕПОДТВЕРЖДЁННОЕ соединение занимает горутину и
	// буферы до пятнадцатисекундного срока рукопожатия, то есть поток соединений — это память
	// хаба и его дескрипторы, а выбирает объём тот, кто стучится. Предел тот же, что у таблицы
	// сессий: законная звезда (32 пира × 4 соединения) в него входит с двойным запасом.
	h := newStand(t).h
	saved := streamMax
	streamMax = 2
	defer func() { streamMax = saved }()

	ln := newErrListener(0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.streamServe(ctx, ln) }()

	// Два молчащих соединения занимают оба места и держат их: рукопожатия не будет.
	var held []net.Conn
	for i := 0; i < 2; i++ {
		srv, cli := net.Pipe()
		ln.conns <- srv
		held = append(held, cli)
	}
	// Ждём, пока оба дойдут до обработчика.
	deadline := time.Now().Add(2 * time.Second)
	for h.streamLive.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := h.streamLive.Load(); got != 2 {
		t.Fatalf("занято мест: %d, хочу 2", got)
	}

	// Третье обязано быть закрыто сразу, а не поставлено в очередь: чтение с него получит EOF.
	srv, cli := net.Pipe()
	ln.conns <- srv
	_ = cli.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := cli.Read(make([]byte, 1)); err == nil {
		t.Fatal("соединение сверх предела не закрыто")
	}
	if got := h.streamLive.Load(); got != 2 {
		t.Fatalf("после отказа занято мест: %d, хочу 2 — место утекло", got)
	}

	// Место освобождается, когда соединение уходит: иначе предел был бы одноразовым.
	held[0].Close()
	deadline = time.Now().Add(3 * time.Second)
	for h.streamLive.Load() > 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := h.streamLive.Load(); got != 1 {
		t.Fatalf("после обрыва занято мест: %d, хочу 1", got)
	}
	for _, c := range held {
		c.Close()
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("streamServe не вышла по отмене контекста")
	}
}

// ---- находка I-129: режим потока не знал про Decoy вовсе ----------------------
//
// streamConn отвечал одним и тем же оповещением на всех четырёх развилках «не наш», а ключ Decoy
// читала только половина поддельного TCP. При этом Hub.Run печатает при подъёме «неопознанным:
// <describe>» независимо от того, поднят ли поддельный TCP: с --stream-only --decoy proxy хаб
// обещал отдавать соединения настоящему серверу и не отдавал никого никому. То есть оператор,
// выбравший proxy ради защиты от активного зондирования, получал alert — поведение, про которое в
// шапке decoy.go прямо написано, что оно отличимо от настоящего сервера с сертификатом.

func TestПотокМолчитПоНастройкеSilent(t *testing.T) {
	st := newStand(t)
	st.h.opt.Decoy = DecoyMode{Mode: "silent"}
	got := streamAnswer(t, st.h, tlsRecord(900))
	if len(got) != 0 {
		t.Errorf("при silent хаб ответил %x, а обещал молчать", got)
	}
	if st.h.stats.strangers.Load() == 0 {
		t.Error("посторонний не сосчитан")
	}
}

func TestПотокОтдаётНеопознанногоПрикрытию(t *testing.T) {
	// Настоящее прикрытие — обычный слушатель в стенде: он записывает то, что ему прислали, и
	// отвечает своей строкой. Проверяется главное свойство дорожки: прибор получает ответ ИМЕННО
	// прикрытия, а прикрытие получает присланный ClientHello ЦЕЛИКОМ и без правок.
	decoy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("нет петли для стенда: %v", err)
	}
	defer decoy.Close()
	gotHello := make(chan []byte, 1)
	go func() {
		c, err := decoy.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		gotHello <- append([]byte(nil), buf[:n]...)
		_, _ = c.Write([]byte("подлинный ответ прикрытия"))
	}()

	st := newStand(t)
	st.h.opt.Decoy = DecoyMode{Mode: "proxy", Dest: decoy.Addr().String(), Timeout: 2 * time.Second}

	hello := tlsRecord(900)
	got := streamAnswer(t, st.h, hello)
	if string(got) != "подлинный ответ прикрытия" {
		t.Errorf("прибор получил %q, а должен был получить ответ прикрытия", got)
	}
	select {
	case sent := <-gotHello:
		if string(sent) != string(hello) {
			t.Errorf("прикрытию ушло %d байт из %d — присланное обязано уходить целиком",
				len(sent), len(hello))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("прикрытие не получило ClientHello вовсе")
	}
	if got := st.h.decoyLive.Load(); got != 0 {
		t.Errorf("место в пределе не возвращено: занято %d", got)
	}
}

func TestПотокПриНеотвечающемПрикрытииОтвечаетОповещением(t *testing.T) {
	// Молчание при неудаче сообщало бы прибору больше, чем оповещение: порт, который завершил
	// рукопожатие TCP и замолчал, в интернете почти не встречается.
	st := newStand(t)
	// Порт, на котором заведомо никого нет: слушатель поднят и сразу закрыт.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("нет петли для стенда: %v", err)
	}
	dead := ln.Addr().String()
	ln.Close()
	st.h.opt.Decoy = DecoyMode{Mode: "proxy", Dest: dead, Timeout: 300 * time.Millisecond}
	got := streamAnswer(t, st.h, tlsRecord(900))
	if string(got) != string(noise.Alert()) {
		t.Errorf("ответ %x, ждали фатальное оповещение %x", got, noise.Alert())
	}
	if got := st.h.decoyLive.Load(); got != 0 {
		t.Errorf("место в пределе не возвращено: занято %d", got)
	}
}
