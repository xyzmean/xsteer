// Пакет client — сторона, которая соединяется: пир звезды xsteer.
//
// УСТРОЙСТВО. На каждое соединение к хабу — свой воркер, и это единица владения: у него своё
// поддельное TCP-соединение, свои ключи, своё смещение в потоке и своё окно приёма. Ничего из
// этого не разделяется, поэтому в самом опасном месте протокола (повтор nonce = полная потеря
// AEAD) нет ни атомиков, ни замков по существу.
//
// ЗАЧЕМ СОЕДИНЕНИЙ НЕСКОЛЬКО. Одно упирается ровно в одно ядро — весь горячий путь это AEAD, и
// распараллелить его внутри одного соединения нельзя, потому что смещение общее. Второе
// соединение — второе ядро. И вторая причина, не менее важная: хаб раскладывает соединения по
// своим воркерам по младшим битам порта источника, а порт случайный, поэтому при одном соединении
// на пира два пира с вероятностью 1/2 попадают в один воркер хаба, и его многопоточность не
// работает вовсе. Соединения с РАЗНЫМИ младшими битами закрывают это.
//
// ЧЕМ ЦИКЛ ОТЛИЧАЕТСЯ ОТ РЕАЛИЗАЦИИ НА C. Там один поток на воркера и один poll на два
// дескриптора; здесь на воркера приходятся три горутины (наружу, обратно, ход времени) с
// блокирующими чтениями. Так этот же код работает и там, где ждать на дескрипторе TUN придётся
// иначе (Wintun вообще не дескриптор), и не приходится держать свой опросчик. Плата — замок вокруг
// номера последовательности; она названа и оценена в шапке пакета link.
package client

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xyzmean/xsteer/conf"
	"github.com/xyzmean/xsteer/link"
	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/route"
	"github.com/xyzmean/xsteer/tun"
	"github.com/xyzmean/xsteer/wire"
)

// Options — что нужно клиенту, чтобы подняться.
type Options struct {
	Conf *conf.Conf
	Sec  *conf.Secrets
	// Device — имя устройства. Пустое означает «выбери сам» (xs0).
	Device string
	// Conns — сколько соединений открыть к хабу. Ноль означает «по одному на ядро, но не больше
	// wire.ConnsMax».
	Conns int
	// AESPreferred — есть ли у процессора аппаратный AES. Решает, какой шифр будет согласован;
	// см. chello.Build. Ноль знаний тут хуже, чем догадка: по умолчанию берётся ответ от
	// платформы (см. cpu.AESPreferred в cmd).
	AESPreferred bool
	// Managed — устройством владеет кто-то другой (служба системы, графический клиент): адрес,
	// MTU и маршруты ему уже задали, и трогать их нельзя.
	Managed bool
	// ProbeEvery — как часто перепроверять путь. Ноль означает wire.ProbeEveryMS.
	ProbeEvery time.Duration
	// StatePath — куда писать состояние в JSON. Пусто — не писать. Секретов там нет по
	// построению: печатает его тот же код, что conf.JSON, и приватного ключа он не видит.
	StatePath string
	// Logf — куда писать журнал. nil означает «в stderr».
	Logf func(format string, args ...any)
	// Routes — направить ли AllowedIPs хаба в устройство. Ложь нужна тогда, когда маршрутами
	// распоряжается кто-то другой.
	Routes bool
}

// Client — поднятый туннель.
type Client struct {
	opt   Options
	hub   hubInfo
	devs  []tun.Device
	guard *link.Guard

	// mtuNow — то, что стоит на УСТРОЙСТВЕ; mtuPub — то, что ПОДТВЕРЖДЕНО пробой пути.
	//
	// Разница нужна: mtuNow в начале равен безопасному низу, и остальные соединения, назвав его
	// хабу, заставляли бы хаб опускать MTU своей сессии на низ, пока пробой не закончится. Хабу
	// называется только подтверждённое.
	mtuNow atomic.Int64
	mtuPub atomic.Int64

	stats struct {
		txPkts, txBytes, rxPkts, rxBytes, dropped atomic.Uint64
		up                                        atomic.Int64 // сколько соединений живо
		lastHandshake                             atomic.Int64
	}

	wg sync.WaitGroup
}

type hubInfo struct {
	addr [4]byte
	port int
	pub  [32]byte
	str  string
}

func (c *Client) logf(f string, a ...any) {
	if c.opt.Logf != nil {
		c.opt.Logf(f, a...)
		return
	}
	fmt.Fprintf(os.Stderr, "xsteer: "+f+"\n", a...)
}

// Run поднимает туннель и работает до отмены контекста.
func Run(ctx context.Context, opt Options) error {
	if opt.Conf == nil || opt.Sec == nil || !opt.Sec.HasPriv {
		return errors.New("нет конфигурации или приватного ключа")
	}
	if len(opt.Conf.Peers) != 1 {
		return errors.New("у пира ровно один хаб")
	}
	c := &Client{opt: opt}
	p := &opt.Conf.Peers[0]
	ip, err := parseIP4(p.Endpoint)
	if err != nil {
		return err
	}
	c.hub = hubInfo{addr: ip, port: p.EndpointPort, pub: p.Pub,
		str: fmt.Sprintf("%s:%d", p.Endpoint, p.EndpointPort)}

	dev := opt.Device
	if dev == "" {
		dev = "xs0"
	}
	conns := opt.Conns
	if conns <= 0 {
		conns = defaultConns()
	}
	if conns > wire.ConnsMax {
		conns = wire.ConnsMax
	}

	devs, err := tun.OpenQueues(dev, conns)
	if err != nil {
		return err
	}
	c.devs = devs
	name := devs[0].Name()
	if len(devs) < conns {
		c.logf("очередей устройства %d вместо %d — работаю меньшим числом соединений", len(devs), conns)
		conns = len(devs)
	}

	// MTU: начинаем с того, что задано (или с потолка), а согласование пути поправит.
	mtu := opt.Conf.MTU
	if mtu == 0 {
		mtu = wire.MTUDefault
	}
	if !opt.Managed {
		cidr := fmt.Sprintf("%s/%d", ip4str(opt.Conf.Addr), opt.Conf.AddrPlen)
		if err := tun.SetAddr(name, cidr); err != nil {
			return fmt.Errorf("не удалось задать адрес %s на %s: %w", cidr, name, err)
		}
		if err := devs[0].SetMTU(mtu); err != nil {
			return fmt.Errorf("не удалось задать MTU: %w", err)
		}
		c.logf("%s: адрес %s, MTU %d (накладные %d)", name, cidr, mtu, wire.Overhead)
		if opt.Routes {
			for _, a := range p.Allowed {
				cidr := fmt.Sprintf("%s/%d", ip4str(a.Net), a.Plen)
				if err := tun.AddRoute(name, cidr); err != nil {
					c.logf("маршрут %s не встал: %v", cidr, err)
				}
			}
		}
	} else {
		if got := tun.DevMTU(name); got > 0 {
			mtu = got
			c.logf("%s: устройством владеет кто-то другой, MTU %d (накладные %d)", name, mtu, wire.Overhead)
			if got > wire.MTUDefault {
				c.logf("ВНИМАНИЕ: MTU %d больше предела %d для канала 1500 — большие пакеты будут "+
					"пропадать; поставьте %d", got, wire.MTUDefault, wire.MTUDefault)
			}
		}
	}
	c.mtuNow.Store(int64(mtu))

	// Правило против RST собственного ядра. Не встало — говорим и работаем: на многих системах
	// локальный RST не мешает, а вот молча притворяться, что защита есть, нельзя.
	if g, err := link.GuardUp(name, p.Endpoint, p.EndpointPort); err != nil {
		c.logf("правило против RST не встало (%v) — сессию может оборвать собственное ядро", err)
	} else {
		c.guard = g
	}
	defer c.guard.Down()

	if conns > 1 {
		c.logf("%s: соединений к хабу %d (по одному на ядро)", name, conns)
	}
	for i := 0; i < conns; i++ {
		c.wg.Add(1)
		go func(id int) {
			defer c.wg.Done()
			c.worker(ctx, id, devs[i%len(devs)], name)
		}(i)
	}
	if opt.StatePath != "" {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.stateLoop(ctx, name)
		}()
	}

	// Отмена контекста ОБЯЗАНА разбудить чтение устройства, и это не мелочь.
	//
	// Чтение TUN блокирующее и про контекст ничего не знает: горутина, стоящая в Read, не выйдет
	// никогда, сколько бы раз контекст ни отменили. Первая версия так и вела себя — по Ctrl-C
	// процесс оставался жить, правило против RST оставалось в nftables, а файл состояния врал «up».
	// Нашлось это не в тесте, а по процессам, оставшимся в системе после живого стенда, — и они
	// потом портили следующие замеры. Закрытие дескриптора здесь и есть способ разбудить чтение.
	go func() {
		<-ctx.Done()
		for _, d := range c.devs {
			d.Close()
		}
	}()

	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
		// Все воркеры ушли сами — так бывает только при отмене: иначе они переподключаются вечно.
	case <-ctx.Done():
		// Отсрочка отсчитывается ТОЛЬКО от отмены, а не от запуска. Первая версия ждала три
		// секунды безусловно — и туннель тихо снимался через три секунды работы: журнал
		// заканчивался на «путь подтвердил пробой», устройство исчезало, ни одной строки об
		// ошибке. Стенд поймал это как «нет /sys/class/net/xsa/mtu».
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			// Кто-то всё-таки не проснулся. Уходим и говорим об этом: висящий процесс хуже, чем
			// незакрытая горутина в процессе, который сейчас завершится.
			c.logf("не все соединения закрылись за 3 с — выхожу")
		}
	}
	return ctx.Err()
}

// defaultConns — по одному соединению на ядро, но не больше предела.
func defaultConns() int {
	n := numCPU()
	if n > wire.ConnsMax {
		n = wire.ConnsMax
	}
	if n < 1 {
		n = 1
	}
	return n
}

// worker — один поддельный соединение к хабу от подъёма до отмены.
func (c *Client) worker(ctx context.Context, id int, dev tun.Device, devName string) {
	for ctx.Err() == nil {
		err := c.session(ctx, id, dev, devName)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.logf("соединение %d: %v", id, err)
		}
		// Пауза перед повтором: без неё неудачное подключение молотило бы сеть, которой ещё нет.
		// Пять секунд — тот же ритм, с каким службу поднимает система.
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// sess — состояние одной сессии (одно рукопожатие).
type sess struct {
	conn *link.Conn
	tx   *noise.Keys
	rx   *noise.Keys
	win  wire.Window
	// mtuAgreed — минимум из пределов сторон; mtuConfirmed — подтверждённый пробой.
	mtuAgreed, mtuConfirmed int
	mtuCap, mtuLimit        int
	mtuTold                 int

	// Границы поиска предела: lo заведомо проходит, hi заведомо нет (0 — пока неизвестно).
	//
	// ВСЕМИ ЭТИМИ ПОЛЯМИ ВЛАДЕЕТ РОВНО ОДНА ГОРУТИНА — timeLoop. Горутина приёма, увидев эхо на
	// пробу, не правит их сама, а кладёт дошедший размер в канал packs. Первая версия правила
	// прямо, и детектор гонок нашёл на этом четыре разных места: снаружи такая гонка выглядела бы
	// как «MTU иногда встаёт не тот», то есть как самый неуловимый класс отказов в этом проекте.
	// Владение одной горутиной здесь дешевле замка и надёжнее внимательности.
	pLo, pHi, pCur, pTries, pSteps int
	pVerify                        bool
	probing                        bool
	probeSent, probeNext           int64

	// packs — дошедшие размеры проб от горутины приёма. Буфер маленький и запись
	// НЕБЛОКИРУЮЩАЯ: потерянное эхо стоит одного повтора пробы, а придержанная горутина приёма
	// стоила бы задержки всему трафику.
	packs chan int
}

func (c *Client) session(ctx context.Context, id int, dev tun.Device, devName string) error {
	// Порт из эфемерного диапазона и новый на каждое подключение: прежняя запись conntrack по
	// дороге может ещё жить, и повтор порта выглядел бы для неё продолжением уже закрытого потока.
	sport := uint16(32768 + rand.IntN(28000))
	sport = sport&^uint16(wire.ConnsMax-1) | uint16(id&(wire.ConnsMax-1))

	raw, err := link.OpenRaw(c.hub.addr, sport, uint16(c.hub.port))
	if err != nil {
		return err
	}
	conn, err := link.Open(raw, c.hub.addr, c.hub.port, id, rand.Uint32(), sport)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Печатается ВСЕГДА и до ожидания. Молчание до конца рукопожатия делает «клиент ничего не
	// делает» неотличимым от «SYN не уходит», и ровно на это уходит первый живой прогон.
	c.logf("соединение %d: подключаюсь к %s с порта %d", id, c.hub.str, conn.SPort)

	s := &sess{conn: conn, packs: make(chan int, 4)}
	s.mtuCap = c.opt.Conf.MTU
	buf := make([]byte, wire.Row)

	// ---- поддельное рукопожатие TCP ----
	deadline := time.Now().Add(link.SynRetryMS * link.SynRetries * time.Millisecond)
	for conn.State() != link.StateEst && time.Now().Before(deadline) && ctx.Err() == nil {
		ok, err := conn.WaitRead(link.TickMS * time.Millisecond)
		if err != nil {
			return err
		}
		if ok {
			seg, mine, err := conn.Recv(buf)
			if err != nil {
				return err
			}
			if mine {
				if _, err := conn.OnSeg(&seg); err != nil {
					// RST на поддельный SYN — это ОТВЕТ, и он говорит больше, чем тишина: на порту
					// либо нет нашего хаба, либо у него не встало правило против RST, и его же
					// ядро рвёт нам сессию.
					return fmt.Errorf("%s ответил RST — на этом порту не наш хаб, либо у хаба не "+
						"встало правило против RST собственного ядра", c.hub.str)
				}
			}
		}
		if err := conn.Tick(); err != nil {
			break
		}
	}
	if conn.State() != link.StateEst {
		return fmt.Errorf("%s не отвечает на поддельный SYN (%d попыток): хаб не запущен, порт "+
			"закрыт, или у хаба не встало правило против RST собственного ядра",
			c.hub.str, link.SynRetries)
	}

	// Предел по каналу считается от НАСТОЯЩЕГО интерфейса, через который мы уходим, а не от
	// предположения «1500»: на PPPoE это 1492, и разница в 8 байт — ровно тот случай, когда
	// большие пакеты пропадают молча.
	linkMTU, linkIf := link.EgressMTU(conn.SAddr)
	if linkMTU > 0 {
		s.mtuLimit = wire.MTU(linkMTU)
	}

	// ---- рукопожатие xsteer ----
	hs := &noise.HS{}
	defer hs.Wipe()
	mtuSay := s.mtuLimit
	if mtuSay == 0 {
		mtuSay = int(c.mtuNow.Load())
	}
	hello, err := hs.ClientHello(c.opt.Sec.Priv, c.hub.pub, c.opt.Conf.SNI, mtuSay, id,
		c.opt.AESPreferred, nil)
	if err != nil {
		return fmt.Errorf("рукопожатие не собралось: %w", err)
	}
	if err := conn.Send(link.PSH|link.ACK, hello); err != nil {
		return err
	}

	// Ответ хаба приходит одним сегментом: он собран так, чтобы влезть. Но склеить два мы всё
	// равно умеем — дешевле, чем однажды не понять, почему рукопожатие не проходит на канале с
	// меньшим MSS.
	var acc []byte
	hsDeadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(hsDeadline) || ctx.Err() != nil {
			return fmt.Errorf("хаб %s не ответил на рукопожатие", c.hub.str)
		}
		ok, err := conn.WaitRead(200 * time.Millisecond)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		seg, mine, err := conn.Recv(buf)
		if err != nil {
			return err
		}
		if !mine {
			continue
		}
		data, err := conn.OnSeg(&seg)
		if err != nil {
			return err
		}
		if !data {
			continue
		}
		acc = append(acc, seg.Payload...)
		s.tx, s.rx, _, err = hs.ClientFinish(acc)
		if errors.Is(err, noise.ErrFormat) && len(acc) < 2*wire.Row {
			continue // ждём остаток
		}
		if err != nil {
			return fmt.Errorf("хаб не признал нас или ответил не тем: %w", err)
		}
		break
	}
	confirm, err := hs.ClientConfirm(s.tx)
	if err != nil {
		return err
	}
	if err := conn.Send(link.PSH|link.ACK, confirm); err != nil {
		return err
	}

	// СОГЛАСОВАНИЕ MTU, ступень первая: минимум из пределов сторон — «максимальное для обоих
	// устройств». Ступень вторая (проверка самого пути пробами) начинается ниже, потому что канал
	// у обоих может быть шире, чем путь между ними.
	peerMTU := int(hs.Peer.MTU)
	s.mtuAgreed = wire.MTUDefault
	if s.mtuLimit > 0 {
		s.mtuAgreed = s.mtuLimit
	}
	if peerMTU > 0 && peerMTU < s.mtuAgreed {
		s.mtuAgreed = peerMTU
	}
	if s.mtuCap > 0 && s.mtuCap < s.mtuAgreed {
		s.mtuAgreed = s.mtuCap
	}
	if linkIf == "" {
		linkIf = "?"
	}
	c.logf("соединение %d: рукопожатие с %s прошло, порт %d, шифр %s", id, c.hub.str, conn.SPort,
		s.tx.Kind())
	c.logf("соединение %d: предел согласован %d (наш канал %s даёт %d, хаб называет %d)", id,
		s.mtuAgreed, linkIf, s.mtuLimit, peerMTU)
	c.stats.up.Add(1)
	c.stats.lastHandshake.Store(time.Now().Unix())
	defer c.stats.up.Add(-1)

	// НАЧИНАЕМ С БЕЗОПАСНОГО НИЗА — главный урок, взятый у veil: пока проба не подтвердила размер,
	// каждый полноразмерный пакет рискует уйти в ту самую чёрную дыру, которую мы ищем. Но только
	// на ПЕРВОМ рукопожатии: переподключение происходит по причинам, к пути не относящимся, и
	// ронять MTU на низ каждый раз значило бы платить провалом скорости за событие, которое к MTU
	// отношения не имеет.
	if id == 0 && c.mtuPub.Load() == 0 && s.mtuAgreed > wire.MTUFloor &&
		int(c.mtuNow.Load()) > wire.MTUFloor {
		c.applyMTU(dev, devName, wire.MTUFloor, "начинаю с безопасного низа, проверяю путь")
	}
	s.mtuConfirmed = int(c.mtuPub.Load())
	c.probeStart(s, id)

	// ---- данные ----
	sctx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); defer stop(); c.outbound(sctx, id, s, dev) }()
	go func() { defer wg.Done(); defer stop(); c.inbound(sctx, id, s, dev, devName) }()
	c.timeLoop(sctx, id, s, dev, devName)
	stop()
	wg.Wait()
	return nil
}

// outbound: TUN → поддельный TCP. Шифрование НА МЕСТЕ, заголовки ПЕРЕД нагрузкой в том же буфере,
// ни одной копии нагрузки.
func (c *Client) outbound(ctx context.Context, id int, s *sess, dev tun.Device) {
	row := make([]byte, wire.Row+wire.Tag)
	for ctx.Err() == nil {
		n, err := dev.Read(row[wire.HdrRoom : wire.HdrRoom+int(c.mtuNow.Load())])
		if err != nil {
			if ctx.Err() == nil {
				c.logf("соединение %d: чтение устройства: %v", id, err)
			}
			return
		}
		if n <= 0 {
			continue
		}
		pt := row[wire.HdrRoom : wire.HdrRoom+n]
		// Подрезка MSS в ОБОИХ направлениях, и это не перестраховка: сюда приходят SYN от узлов
		// локальной сети, а из туннеля — SYN-ACK от узлов интернета, которые объявляют MSS по
		// СВОЕМУ каналу и ничего не знают про наш.
		route.MSSClamp(pt, int(c.mtuNow.Load()))
		if err := c.sendFrame(s, row, n); err != nil {
			c.stats.dropped.Add(1)
			if errors.Is(err, link.ErrDead) {
				return
			}
			continue
		}
		c.stats.txPkts.Add(1)
		c.stats.txBytes.Add(uint64(n))
		// Ретайр: смещение подошло к пределу или соединение старое. Замолчать ОБЯЗАНЫ — иначе
		// повтор nonce, то есть полная потеря защиты AEAD.
		if wire.RetireDue(s.conn.RelNext(), s.conn.Age()) {
			c.logf("соединение %d: смена ключей — поднимаю соединение заново", id)
			return
		}
	}
}

// sendFrame шифрует кадр открытого текста, лежащий по row[wire.HdrRoom:], и отправляет его.
//
// Служебные кадры (проба, эхо, итог) уходят тем же путём, что данные: у них нет своего канала, и
// это нарочно — иначе появился бы второй путь на проводе, который DPI различал бы по размеру и
// ритму.
func (c *Client) sendFrame(s *sess, row []byte, n int) error {
	rel := s.conn.RelNext()
	rec := row[wire.HdrRoom-wire.RecHdr : wire.HdrRoom]
	if err := wire.RecBuild(rec, n+wire.Tag); err != nil {
		return err
	}
	if _, err := s.tx.Seal(row[wire.HdrRoom:wire.HdrRoom+n+wire.Tag], n, rec, uint64(rel)); err != nil {
		return err
	}
	got, err := s.conn.SendData(row, wire.RecHdr+n+wire.Tag)
	if err != nil {
		return err
	}
	if got != rel {
		// Такого быть не может: смещение читается и тратится под одним замком. Проверка стоит
		// одного сравнения и ловит единственную ошибку, которая иначе не видна вообще никак —
		// разъезд номера на проводе и номера в nonce.
		return fmt.Errorf("смещение разошлось: шифровали %d, отправили %d", rel, got)
	}
	return nil
}

// inbound: поддельный TCP → TUN.
func (c *Client) inbound(ctx context.Context, id int, s *sess, dev tun.Device, devName string) {
	buf := make([]byte, wire.Row)
	for ctx.Err() == nil {
		ok, err := s.conn.WaitRead(200 * time.Millisecond)
		if err != nil {
			return
		}
		if !ok {
			continue
		}
		seg, mine, err := s.conn.Recv(buf)
		if err != nil {
			return
		}
		if !mine {
			continue
		}
		data, err := s.conn.OnSeg(&seg)
		if err != nil {
			c.logf("соединение %d: %v", id, err)
			return
		}
		if !data {
			continue
		}
		// Предфильтр до всякой криптографии: три сравнения отбивают чужое.
		body, err := wire.RecParse(seg.Payload)
		if err != nil {
			continue
		}
		rel := s.conn.RelOf(seg.Seq)
		if !s.win.Check(rel) {
			continue
		}
		pt, err := s.rx.Open(body, seg.Payload[:wire.RecHdr], uint64(rel))
		if err != nil {
			continue
		}
		// Коммит окна ТОЛЬКО после сошедшегося тега: иначе подделанный пакет с далёким смещением
		// выбил бы из окна весь честный поток.
		s.win.Commit(rel)
		switch wire.FrameKind(pt) {
		case wire.KindIPv4, wire.KindIPv6:
			route.MSSClamp(pt, int(c.mtuNow.Load()))
			if _, err := dev.Write(pt); err != nil {
				c.stats.dropped.Add(1)
				continue
			}
			c.stats.rxPkts.Add(1)
			c.stats.rxBytes.Add(uint64(len(pt)))
		case wire.KindCtl:
			// Эхо на пробу пути — единственный служебный кадр, который клиент получает. Остальное
			// молча пропускаем: неизвестный служебный кадр от новой версии хаба не повод рвать
			// туннель.
			if acked := wire.PackSize(pt); acked > 0 {
				select {
				case s.packs <- acked:
				default:
				}
			}
		}
		// keepalive молча учтён: он уже обновил время последнего приёма.
	}
}

// onPack — дошедший размер пробы. Зовётся ТОЛЬКО из timeLoop: этой горутине принадлежит всё
// состояние поиска предела (см. sess).
func (c *Client) onPack(s *sess, id, acked int, dev tun.Device, devName string) {
	if !s.probing || acked != s.pCur {
		return
	}
	// Размер вернулся эхом — путь его несёт. Двигаем нижнюю границу и спрашиваем, есть ли смысл
	// проверять дальше.
	s.pLo = acked
	s.pTries = 0
	s.pVerify = false
	s.pCur = wire.MTUNext(s.pLo, s.pHi, s.mtuAgreed)
	s.pSteps++
	if s.pCur == 0 || s.pSteps > wire.MTUTriesMax {
		c.probeDone(s, id, dev, devName)
	} else {
		s.probeSent = 0
	}
}

// timeLoop — ход времени: подтверждения, keepalive, пробы пути, пределы соединения.
func (c *Client) timeLoop(ctx context.Context, id int, s *sess, dev tun.Device, devName string) {
	t := time.NewTicker(link.TickMS * time.Millisecond)
	defer t.Stop()
	keepalive := int64(c.opt.Conf.Peers[0].Keepalive) * 1000
	for {
		select {
		case <-ctx.Done():
			return
		case acked := <-s.packs:
			c.onPack(s, id, acked, dev, devName)
			continue
		case <-t.C:
		}
		if err := s.conn.Tick(); err != nil {
			c.logf("соединение %d: путь молчит %d мс при активной отправке — поднимаю заново",
				id, link.DeadMS)
			return
		}
		now := time.Now().UnixNano() / int64(time.Millisecond)

		if s.probing {
			if s.probeSent == 0 || now-s.probeSent >= wire.ProbeWaitMS {
				if s.probeSent != 0 {
					s.pTries++
					if s.pTries >= wire.ProbeTries {
						// Не подтвердился после повторов — считаем размер непроходящим. Повторы
						// обязательны: у пробы нет повторной передачи, и одна случайная потеря не
						// должна означать «путь этого не несёт».
						s.pHi = s.pCur
						s.pTries = 0
						if s.pVerify {
							// Прежнее значение больше не проходит. Опускаемся НЕМЕДЛЕННО, не
							// дожидаясь конца поиска: пока он идёт, каждый полный пакет пропадал бы.
							s.pVerify = false
							c.logf("путь больше не несёт %d — опускаюсь на %d и ищу новый предел",
								s.pCur, wire.MTUFloor)
							c.applyMTU(dev, devName, wire.MTUFloor, "путь сузился, ищу новый предел")
						}
						s.pCur = wire.MTUNext(s.pLo, s.pHi, s.mtuAgreed)
						s.pSteps++
						if s.pCur == 0 || s.pSteps > wire.MTUTriesMax {
							c.probeDone(s, id, dev, devName)
							continue
						}
					}
				}
				if s.pCur > 0 {
					probe := make([]byte, wire.HdrRoom+s.pCur+wire.Tag)
					if n, ok := wire.ProbeBuild(probe[wire.HdrRoom:wire.HdrRoom+s.pCur], s.pCur); ok {
						_ = c.sendFrame(s, probe, n)
					}
					s.probeSent = now
				}
			}
		} else if s.probeNext != 0 && now >= s.probeNext {
			// Повторная проверка под живой сессией: путь меняется (смена маршрута у провайдера,
			// переход между точками WiFi), и без этого суженный путь глотал бы полноразмерные
			// кадры до конца сессии.
			c.probeStart(s, id)
		}

		// Соединения кроме нулевого НАЗЫВАЮТ хабу согласованный MTU: у каждого соединения на хабе
		// своя сессия, и подрезку MSS для обратного трафика хаб делает по MTU ТОЙ сессии, в которую
		// отправляет. Не сказав, мы получили бы «через одно соединение большие пакеты ходят, через
		// другое нет».
		if id != 0 {
			if pub := int(c.mtuPub.Load()); pub > 0 && s.mtuTold != pub {
				frame := make([]byte, wire.HdrRoom+8+wire.Tag)
				n := wire.MTUBuild(frame[wire.HdrRoom:wire.HdrRoom+8], pub)
				if n > 0 && c.sendFrame(s, frame, n) == nil {
					s.mtuTold = pub
				}
			}
		}

		// Keepalive: пустая запись. Пир за NAT обязан поддерживать отображение живым, потому что
		// дозвониться до него хаб не может.
		if keepalive > 0 && s.conn.SinceTX() >= keepalive {
			frame := make([]byte, wire.HdrRoom+wire.Tag)
			_ = c.sendFrame(s, frame, 0)
		}
	}
}

// probeStart начинает проверку пути.
//
// ПОЧЕМУ ПОВТОРНЫЙ ПРОБОЙ НАЧИНАЕТСЯ С ПРОВЕРКИ УЖЕ НАЙДЕННОГО, А НЕ С ПОПЫТКИ ПОДНЯТЬ. Путь
// меняется под живой сессией в ОБЕ стороны. Поиск, который умеет только поднимать предел, при
// сузившемся пути оставит нас на прежнем значении: мелкие пакеты ходят, большие пропадают целиком
// и молча.
func (c *Client) probeStart(s *sess, id int) {
	// Путь у всех соединений один — тот же канал, тот же хаб, — поэтому проверяет его ОДИН воркер.
	// Четыре независимых пробоя дали бы вчетверо больше служебных кадров и четыре мнения об одном
	// и том же числе.
	if id != 0 {
		s.probing = false
		return
	}
	s.pTries, s.pSteps, s.probeSent = 0, 0, 0
	s.pLo, s.pHi = wire.MTUFloor, 0
	if s.mtuConfirmed > wire.MTUFloor {
		s.pVerify = true
		s.pCur = s.mtuConfirmed
		s.probing = true
		return
	}
	s.pVerify = false
	s.pCur = wire.MTUNext(s.pLo, s.pHi, s.mtuAgreed)
	s.probing = s.pCur > 0
}

// probeDone применяет найденное и сообщает хабу.
func (c *Client) probeDone(s *sess, id int, dev tun.Device, devName string) {
	s.probing = false
	s.pVerify = false
	every := c.opt.ProbeEvery
	if every <= 0 {
		every = wire.ProbeEveryMS * time.Millisecond
	}
	s.probeNext = time.Now().Add(every).UnixNano() / int64(time.Millisecond)
	if s.pLo <= wire.MTUFloor {
		// Не подтвердился ни один размер выше низа. Остаёмся на нём — и ГОВОРИМ об этом: молча
		// работать вдвое медленнее возможного это ровно тот отказ, который никто не заметит.
		c.logf("путь не подтвердил ни один размер выше %d — остаюсь на нём. Похоже, пробы не "+
			"доходят вовсе", wire.MTUFloor)
		c.applyMTU(dev, devName, wire.MTUFloor, "путь не подтвердил ничего выше низа")
		s.mtuConfirmed = 0
		return
	}
	// Сравнение — с тем, что СТОИТ НА УСТРОЙСТВЕ, а не с прошлым подтверждённым значением.
	// Разница стоила живого туннеля в реализации на C: после переподключения устройство сидело на
	// безопасном низу, подтверждённое значение осталось прежним, проверка «ничего не изменилось»
	// срабатывала — и туннель оставался на 1200 при пути, несущем 1387, до перезапуска.
	grew := s.pLo > int(c.mtuNow.Load())
	s.mtuConfirmed = s.pLo
	c.mtuPub.Store(int64(s.pLo))
	why := "путь сузился"
	if grew {
		why = "путь подтвердил пробой"
	}
	c.applyMTU(dev, devName, s.pLo, why)
	frame := make([]byte, wire.HdrRoom+8+wire.Tag)
	if n := wire.MTUBuild(frame[wire.HdrRoom:wire.HdrRoom+8], s.pLo); n > 0 {
		_ = c.sendFrame(s, frame, n)
	}
}

// applyMTU ставит устройству новый MTU. Значение, заданное человеком в конфигурации, никогда не
// превышается: если он написал 1380, мы не поставим 1431, даже если путь его несёт.
func (c *Client) applyMTU(dev tun.Device, devName string, mtu int, why string) {
	if cap := c.opt.Conf.MTU; cap > 0 && mtu > cap {
		mtu = cap
	}
	old := int(c.mtuNow.Load())
	if mtu == old {
		return
	}
	if err := dev.SetMTU(mtu); err != nil {
		c.logf("%s: не удалось поставить MTU %d: %v", devName, mtu, err)
		return
	}
	c.logf("%s: MTU %d → %d (%s)", devName, old, mtu, why)
	c.mtuNow.Store(int64(mtu))
}
