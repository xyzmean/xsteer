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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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
	// NoOffload — не включать разгрузку сегментации устройства.
	//
	// Ключ существует не для настройки, а для РАЗБИРАТЕЛЬСТВА: разгрузка меняет то, как выглядит
	// путь данных (склейка на отправке, нарезка на приёме), и когда однажды придётся выяснять, не
	// она ли виновата, единственный честный способ — прогнать то же самое без неё и сравнить.
	NoOffload bool
	// Routes — направить ли AllowedIPs хаба в устройство. Ложь нужна тогда, когда маршрутами
	// распоряжается кто-то другой.
	Routes bool
	// Stream — вести записи по НАСТОЯЩЕМУ соединению TCP вместо поддельного.
	//
	// Нужно там, где поддельный TCP недоступен (Windows без драйвера-перехватчика) — и, возможно,
	// везде: настоящий стек бесплатно даёт всё, что мы изображаем руками. Цена — TCP внутри TCP;
	// решает замер, см. шапку wire/stream.go.
	Stream bool
	// StreamPort — порт хаба для режима потока. Ноль означает порт из Endpoint. Отдельный порт
	// нужен потому, что слушающий сокет ядра на порту поддельного TCP отвечал бы SYN-ACK и
	// поддельным пирам тоже.
	StreamPort int
	// KillSwitch — не возвращать маршрут по умолчанию физическому интерфейсу, даже если туннель
	// перестал нести трафик.
	//
	// Выбор между двумя бедами, и он принадлежит человеку, а не программе. Без ключа умерший
	// туннель отдаёт маршрут обратно: связь важнее, и «интернет пропал» не случается. С ключом
	// маршрут остаётся в мёртвом туннеле: трафик не пойдёт вовсе, но и наружу открытым не
	// выйдет. Второе нужно тому, для кого утечка дороже простоя.
	KillSwitch bool
	// NoBatch — не собирать кадры в одну запись и не разрезать записи между сегментами.
	//
	// Нужно ровно для одного: разговора с хабом на C, который ни пачек, ни сборки пока не умеет.
	// Пока перенос в C не сделан, это единственный способ подключить десктоп к уже работающему
	// серверу — и цена названа прямо: облик на проводе возвращается к тому, который отличается от
	// настоящего TLS первым же признаком (запись всегда кончается на границе сегмента).
	NoBatch bool
}

// Client — поднятый туннель.
type Client struct {
	opt   Options
	hub   hubInfo
	devs  []tun.Device
	guard *link.Guard

	// dialControl — хук, привязывающий НАШ сокет к физическому интерфейсу, чтобы соединение к
	// хабу не уходило в туннель. nil означает «привязки нет»: либо система её не требует
	// (Linux), либо не удалось — тогда роль обхода играет маршрут /32.
	dialControl func(network, address string, c syscall.RawConn) error

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
		// lastRx — когда от хаба в последний раз пришёл ХОТЬ КАКОЙ-ТО разобранный кадр, в
		// миллисекундах. Отдельно от rxBytes: те считают только пользовательские пакеты, а
		// доказательством живости служит и служебное эхо на пробу.
		lastRx atomic.Int64
	}

	// ---- слежение за сетью (netwatch_*.go) ----
	//
	// netGen — поколение сети: растёт, когда путь к хабу изменился (адрес выхода стал другим,
	// пропал или появился). Живые соединения сверяются с ним и поднимаются заново сами; ждать при
	// этом ни тишины, ни ошибки отправки не нужно.
	netGen atomic.Uint64
	// netMu и netWait — оповещение ждущих. Канал ЗАКРЫВАЕТСЯ на изменении и заменяется новым:
	// закрытие — единственный способ разбудить сразу всех, не заводя списка подписчиков.
	netMu   sync.Mutex
	netWait chan struct{}

	wg sync.WaitGroup
}

// netChanged — канал, который закроется при следующем изменении сети.
func (c *Client) netChanged() <-chan struct{} {
	c.netMu.Lock()
	defer c.netMu.Unlock()
	if c.netWait == nil {
		c.netWait = make(chan struct{})
	}
	return c.netWait
}

// bumpNet объявляет, что сеть изменилась: поколение вперёд, все ждущие разбужены.
func (c *Client) bumpNet() {
	c.netGen.Add(1)
	c.netMu.Lock()
	if c.netWait != nil {
		close(c.netWait)
		c.netWait = nil
	}
	c.netMu.Unlock()
}

// linkEgress — обёртка над link.EgressAddr под одним именем для netwatch_*.go обеих платформ.
func linkEgress(daddr [4]byte) ([4]byte, error) { return link.EgressAddr(daddr) }

type hubInfo struct {
	addr [4]byte
	port int
	pub  [32]byte
	str  string
}

// Обратная связь по сборке разрезанных записей.
const (
	// reasmCooldownMS — сколько везти по одному кадру после жалобы той стороны. Десять секунд:
	// достаточно, чтобы всплеск потерь прошёл, и мало, чтобы не терять выигрыш пачек надолго.
	reasmCooldownMS = 10000
	// reasmReportMS — как часто сообщать о несобравшихся записях. Две секунды: чаще — лишний
	// служебный трафик, реже — та сторона слишком долго везёт пачками в рвущийся путь.
	reasmReportMS = 2000
	// reasmGrowMS — как быстро наращивать пачку обратно на чистом пути.
	reasmGrowMS = 3000
)

// ---- потолок MTU и буфер продолжения разрезанной записи ----------------------
//
// Числа выведены одно из другого и стоят рядом — то же правило, что у размеров в шапке wire.go и у
// того же потолка в хабе (hub.mtuCeil): иначе одно поправят, а второе останется, и расхождение
// проявится как «мелкие пакеты ходят, крупные молча пропадают», худший класс отказов в диагностике.
const (
	// mtuCeil — потолок РАБОЧЕГО MTU туннеля. Больше в кадр Ethernet вместе с нашими накладными не
	// влезает, поэтому это же число зажимает всё, что приходит извне: MTU чужого устройства
	// (devMTU), число из конфигурации и результат пробоя пути (applyMTU).
	mtuCeil = wire.MTUDefault
	// maxSegCeil — самый большой сегмент, какой может получиться при разрезании записи: то же
	// выражение, что считает sendFrames, но при предельном MTU. 1460 байт — ровно кадр 1500 минус
	// заголовки IP и TCP, дальше некуда.
	maxSegCeil = mtuCeil + wire.Overhead - 40
	// contLen — размер буфера продолжения разрезанной записи (см. outbound и link.SendRecord):
	// заголовок TCP плюс предельный сегмент.
	//
	// Считается ОТ ПОТОЛКА, а не от строки пакета на проводе, и это не косметика. Пока он был
	// 20+Row = 1520, он держал рабочий MTU только до 1479 — а сверху MTU не проверялся вовсе:
	// значение чужого устройства бралось как есть, с одним предупреждением в журнал. При MTU
	// устройства 1480 и выше КАЖДАЯ разрезаемая запись отваливалась в «мал буфер под продолжение
	// записи» и уходила в счётчик отброшенных молча. Теперь оба числа выведены из mtuCeil и
	// разойтись не могут (I-089 в хабе — то же самое).
	contLen = 20 + maxSegCeil
)

// clampMTU — зажать рабочий MTU потолком. Ноль и отрицательное значат «не выяснено» и дают потолок:
// именно с него начинает согласование, а пробой пути опустит его, если путь уже.
//
// ОДНА ФУНКЦИЯ НА ВСЕ ВХОДЫ, и это главное в ней. Предупреждать о числе больше предела клиент умел и
// раньше — не хватало ровно того, чтобы предупреждение чем-то заканчивалось.
func clampMTU(mtu int) int {
	if mtu <= 0 || mtu > mtuCeil {
		return mtuCeil
	}
	return mtu
}

func nowMS() int64 { return time.Now().UnixNano() / int64(time.Millisecond) }

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

	open := tun.OpenQueues
	if opt.NoOffload {
		open = tun.OpenQueuesPlain
	}
	devs, err := open(dev, conns)
	if err != nil {
		return err
	}
	c.devs = devs
	name := devs[0].Name()
	if len(devs) < conns {
		// На Windows это НОРМА, а не беда: у Wintun одна сессия на адаптер, поэтому очередь одна
		// и соединение к хабу тоже одно. Скорость от этого страдает только на многоядерном
		// шифровании; на обычном канале предел не здесь.
		if runtime.GOOS == "windows" {
			c.logf("устройство даёт одну очередь (так устроен Wintun) — работаю одним соединением")
		} else {
			c.logf("очередей устройства %d вместо %d — работаю меньшим числом соединений", len(devs), conns)
		}
		conns = len(devs)
	}

	// MTU: начинаем с того, что задано (или с потолка), а согласование пути поправит. Число из
	// конфигурации зажимается тем же потолком, что и всё остальное: конфигурация принимает MTU до
	// 1500 (conf.go, «576..1500»), то есть человек может написать туда MTU КАНАЛА вместо MTU
	// туннеля — оба ведь называются «MTU», — и без потолка это давало отвал каждой разрезаемой
	// записи.
	mtu := clampMTU(opt.Conf.MTU)
	if opt.Conf.MTU > mtuCeil {
		c.logf("MTU %d из настроек больше предела %d для канала 1500 — работаю на %d",
			opt.Conf.MTU, mtuCeil, mtu)
	}
	if !opt.Managed {
		cidr := fmt.Sprintf("%s/%d", ip4str(opt.Conf.Addr), opt.Conf.AddrPlen)
		if err := tun.SetAddr(name, cidr); err != nil {
			return fmt.Errorf("не удалось задать адрес %s на %s: %w", cidr, name, err)
		}
		if err := devs[0].SetMTU(mtu); err != nil {
			return fmt.Errorf("не удалось задать MTU: %w", err)
		}
		// Очередь устройства — третья команда подъёма, и звать её можно только здесь, внутри
		// !Managed: при --managed адрес, MTU и очередь задал владелец устройства, и спорить с ним
		// значило бы затирать его настройку своей.
		if err := tun.SetTxQueueLen(name, tun.TxQueueLen); err != nil {
			c.logf("%s: очередь передачи осталась ядерной (%v) — просили %d пакетов; ждать чтения "+
				"их сможет меньше, остальные ядро на пиках отбросит", name, err, tun.TxQueueLen)
		}
		c.logf("%s: адрес %s, MTU %d (накладные %d)", name, cidr, mtu, wire.Overhead)
		c.logf("%s: %s", name, offloadLine(devs[0]))
		if len(opt.Conf.DNS) > 0 {
			if err := tun.SetDNS(name, opt.Conf.DNS); err != nil {
				c.logf("серверы имён не заданы (%v) — запросы пойдут прежним резолвером", err)
			} else {
				c.logf("%s: серверы имён %s", name, strings.Join(opt.Conf.DNS, ", "))
			}
		}
		if opt.Routes {
			cidrs := make([]string, 0, len(p.Allowed))
			for _, a := range p.Allowed {
				cidrs = append(cidrs, fmt.Sprintf("%s/%d", ip4str(a.Net), a.Plen))
			}
			// Своё соединение к хабу нельзя пускать в туннель — иначе туннель съедает сам себя.
			// Исключать надо СОКЕТ, а не адрес: привязка сокета к физическому интерфейсу
			// (IP_UNICAST_IF) уводит мимо туннеля только наши пакеты, а чужой трафик к тому же
			// адресу — ssh на этот сервер, например — идёт туннелем, как и ожидается.
			//
			// Читать физический интерфейс надо ДО того, как встанут маршруты туннеля: после они
			// накрывают адрес хаба и «лучшим» окажется сам туннель.
			var bypass []string
			if ctl, idx, err := tun.DialControl(name); err == nil {
				c.dialControl = ctl
				c.logf("своё соединение к хабу привязано к интерфейсу %d — трафик к %s остаётся "+
					"в туннеле", idx, p.Endpoint)
			} else {
				// Привязать не удалось: возвращаемся к маршруту-обходу. Он хуже — выносит из
				// туннеля весь трафик к адресу хаба, — но лучше туннеля, который не поднимется.
				bypass = []string{p.Endpoint}
				c.logf("сокет привязать не удалось (%v) — ставлю обход /32 к %s; учтите, что "+
					"весь трафик к этому адресу пойдёт мимо туннеля", err, p.Endpoint)
			}
			// Снимаем маршруты при выходе тем же TeardownRoutes: обход живёт на физическом
			// интерфейсе и сам не исчезнет.
			full, err := tun.SetupRoutes(name, cidrs, bypass)
			if err != nil {
				// ВНИМАНИЕ, а не просто сообщение: недоставший маршрут означает, что часть
				// адресов ходит мимо туннеля, и заметить это по поведению трудно — интернет
				// работает, а отдельные адреса «не идут через VPN».
				c.logf("ВНИМАНИЕ: %v — эти адреса пойдут МИМО туннеля", err)
			} else {
				c.logf("%s: в туннель направлено префиксов %d", name, len(cidrs))
			}
			defer tun.TeardownRoutes(name)
			// Полный туннель забирает маршрут по умолчанию не здесь, а после доказательства
			// работоспособности — этим занят сторож.
			if full {
				c.wg.Add(1)
				go func() {
					defer c.wg.Done()
					c.routeGuard(ctx, name)
				}()
			}
		}
	} else {
		if got := tun.DevMTU(name); got > 0 {
			mtu = c.devMTU(name, got)
		}
	}
	c.mtuNow.Store(int64(mtu))

	// Правило против RST собственного ядра нужно только поддельному TCP: в режиме потока сессию
	// ведёт сам стек, и гасить его же RST не надо — он их и не порождает.
	if opt.Stream {
		// ничего не ставим
	} else if g, err := link.GuardUp(name, p.Endpoint, p.EndpointPort); err != nil {
		c.logf("правило против RST не встало (%v) — сессию может оборвать собственное ядро", err)
	} else {
		c.guard = g
	}
	defer c.guard.Down()

	if conns > 1 {
		c.logf("%s: соединений к хабу %d (по одному на ядро)", name, conns)
	}
	// Слежение за сетью поднимается ДО соединений: смена сети во время первого подключения — самый
	// обычный случай (служба стартует, пока интерфейс ещё поднимается), и заметить её надо сразу.
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.watchNet(ctx)
	}()
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

	// Устройства закрываются ПОСЛЕ того, как воркеры ушли, и никогда до.
	//
	// Прежде отмена контекста будила чтение закрытием дескриптора устройства прямо из отдельной
	// горутины — считалось, что иначе горутина, стоящая в Read, не выйдет никогда. Для Linux это
	// давно неверно: чтение неблокирующее, ожидание идёт через WaitRead с таймаутом 200 мс, а
	// условие цикла проверяет ctx.Err(). То есть воркеры уходят сами, и закрытие лишь укорачивало
	// эти 200 мс — ценой окна, в котором номер дескриптора уже свободен, а воркеры всё ещё
	// обращаются по нему. Чем это окно опасно и почему совпадает со снятием обвязки — в шапке
	// drainThenClose (I-109).
	//
	// Урок, ради которого побудка появилась, при этом никуда не делся: по Ctrl-C процесс обязан
	// уйти, иначе правило против RST остаётся в nftables, а файл состояния врёт «up». Его держит
	// не закрытие, а отсрочка ниже и то, что каждый цикл смотрит на контекст.
	if !drainThenClose(ctx, &c.wg, 3*time.Second, c.closeDevs) {
		// Кто-то всё-таки не проснулся. Уходим и говорим об этом: висящий процесс хуже, чем
		// незакрытая горутина в процессе, который сейчас завершится. Устройства при этом НЕ
		// закрываем — их номера ещё в работе, а заберёт их выход процесса.
		c.logf("не все соединения закрылись за 3 с — выхожу, устройство оставляю открытым")
	}
	return ctx.Err()
}

// closeDevs закрывает очереди устройства. Зовётся ТОЛЬКО из drainThenClose и только после того,
// как воркеры ушли: закрытый номер дескриптора немедленно достаётся следующему, кто откроет
// что-нибудь, — а этим следующим в момент завершения оказывается труба к nft или ip.
// offloadLine — строка про разгрузку сегментации устройства. Печатается ВСЕГДА: разница в скорости
// здесь измеряется разами (замер: 3920 нс на пакет против 269 нс), поэтому «почему медленно» не
// должно требовать догадок. Проверка через утверждение типа, а не через метод интерфейса: разгрузка
// есть только на Linux, и знание об этом обязано остаться в пакете tun.
func offloadLine(d tun.Device) string {
	o, ok := d.(interface{ Offload() (bool, string) })
	if !ok {
		return "разгрузка сегментации: нет на этой системе"
	}
	on, why := o.Offload()
	if on {
		return "разгрузка сегментации устройства: включена (склейка пакетов в супер-кадр)"
	}
	return "разгрузка сегментации устройства: НЕТ (" + why + ") — путь по одному пакету"
}

func (c *Client) closeDevs() {
	for _, d := range c.devs {
		d.Close()
	}
}

// Сторож маршрута по умолчанию.
const (
	// guardTick — как часто сторож смотрит на живость. Секунда: реагировать быстрее незачем,
	// медленнее — значит дольше держать человека без сети.
	guardTick = time.Second
	// guardFresh — насколько свежим должен быть последний кадр от хаба, чтобы у туннеля появилось
	// ПРАВО взять маршрут по умолчанию. Пять секунд: проба уходит раз в две, так что три
	// пропущенных подряд — уже не случайность.
	guardFresh = 5 * time.Second
	// guardTrial — испытательный срок: сколько ждать ПЕРВОГО настоящего пакета после того, как
	// маршрут по умолчанию уведён в туннель.
	//
	// Отдельная ступень нужна потому, что эхо на пробу НЕ доказывает пересылки. Стенд показал
	// ровно такой хаб: пробы он отражает (значит жив и ключи сошлись), а IP-пакеты не везёт
	// никуда. По одному эху туннель выглядел работающим, и маршрут уходил в никуда.
	//
	// Восемь секунд — это ровно то время, на которое человек остаётся без сети, если хаб не
	// пересылает трафик, поэтому оно взято по нижней границе разумного: рабочий туннель
	// возвращает первый же пакет за миллисекунды, а не за секунды. Простой машины на приговор не
	// влияет — если мы сами ничего не отправили, судить не о чем, и срок продлевается.
	guardTrial = 8 * time.Second
	// guardStall — сколько терпеть отсутствие ответов на УЖЕ подтверждённом туннеле.
	//
	// Пятнадцать секунд, а не пять: маршрут отдаётся дороже, чем берётся. Короткая пауза бывает
	// от смены сети или сна машины, и дёргать маршрут на каждой было бы хуже самой болезни.
	guardStall = 15 * time.Second
	// guardBackoff — пауза после неудачного испытания. Без неё сторож брал бы маршрут и отдавал
	// его по кругу, и человек получал бы сеть, мигающую раз в десять секунд, — это хуже, чем
	// честное «туннель не поднялся».
	guardBackoff = 60 * time.Second
	// guardQuiet — как часто повторять жалобу, пока туннель не ожил. Раз в полминуты: чаще —
	// журнал, в котором не видно ничего другого.
	guardQuiet = 30 * time.Second
)

// routeGuard решает, держит ли туннель маршрут по умолчанию.
//
// ЗАЧЕМ ОН ЕСТЬ. Полный туннель забирает весь исходящий трафик машины. Если канал при этом
// ничего не несёт, у человека не «не работает VPN», у него НЕ РАБОТАЕТ ИНТЕРНЕТ — и отличить
// одно от другого снаружи нечем: браузер одинаково молчит. Именно так и выглядел отказ на живом
// стенде, и лечился он только Ctrl-C.
//
// ЧТО СЧИТАЕТСЯ ДОКАЗАТЕЛЬСТВОМ. Рукопожатие — не доказательство: хаб может узнать нас, принять
// и подтвердить каждый сегмент и не отправить обратно ничего. Доказательство — кадр ОТ хаба:
// эхо на пробу или пользовательский пакет. Пока его нет, маршрут по умолчанию остаётся у
// физического интерфейса, и человек просто видит «туннель не поднялся» при работающей сети.
//
// ЧТО БУДЕТ, ЕСЛИ ТУННЕЛЬ УМРЁТ ПОЗЖЕ. Сторож вернёт маршрут обратно. Это осознанный выбор в
// пользу связи, а не в пользу тайны: трафик, который шёл в туннель, пойдёт открыто. Кому нужно
// обратное — тому --kill-switch, и тогда сторож маршрут не отдаёт никогда.
func (c *Client) routeGuard(ctx context.Context, name string) {
	t := time.NewTicker(guardTick)
	defer t.Stop()

	// Состояния сторожа. Испытание отделено от подтверждения намеренно: право взять маршрут даёт
	// живость хаба, а удержать — только настоящие пакеты.
	const (
		stWait  = iota // маршрут у физического интерфейса, ждём живости хаба
		stTrial        // маршрут в туннеле, ждём ПЕРВОГО настоящего пакета
		stOK           // туннель подтверждён пакетами
	)
	state := stWait
	var lastQuiet, trialStart, retryAfter int64
	var txAt, rxAt uint64 // снимки счётчиков на начало окна ожидания
	var okSince int64

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := nowMS()
		lastFrame := c.stats.lastRx.Load()
		alive := lastFrame != 0 && now-lastFrame < guardFresh.Milliseconds()
		tx, rx := c.stats.txPkts.Load(), c.stats.rxPkts.Load()

		switch state {
		case stWait:
			if !alive || now < retryAfter {
				if now-lastQuiet >= guardQuiet.Milliseconds() {
					why := "хаб не прислал ни одного кадра"
					if now < retryAfter {
						why = fmt.Sprintf("испытание не прошло, следующая попытка через %d с",
							(retryAfter-now)/1000)
					} else if lastFrame != 0 {
						why = fmt.Sprintf("от хаба ничего нет %d с", (now-lastFrame)/1000)
					}
					c.logf("полный туннель НЕ включён: %s. Сеть работает как обычно", why)
					lastQuiet = now
				}
				continue
			}
			if err := tun.DefaultRouteUp(name); err != nil {
				c.logf("маршрут по умолчанию не удалось увести в туннель: %v", err)
				retryAfter = now + guardBackoff.Milliseconds()
				continue
			}
			state, trialStart, txAt, rxAt = stTrial, now, tx, rx
			c.logf("%s: хаб отвечает — пробую увести маршрут по умолчанию в туннель "+
				"(испытание %d с)", name, int(guardTrial.Seconds()))

		case stTrial:
			if rx > rxAt {
				state, okSince = stOK, now
				c.logf("%s: туннель понёс трафик — полный туннель включён", name)
				continue
			}
			if now-trialStart < guardTrial.Milliseconds() {
				continue
			}
			// Срок вышел. Если мы за это время ничего и не отправляли, судить не о чем: машина
			// просто молчала. Продлеваем, а не караем — иначе туннель на простаивающей машине
			// снимался бы сам собой.
			if tx == txAt {
				trialStart = now
				continue
			}
			if c.opt.KillSwitch {
				state, okSince = stOK, now
				c.logf("%s: за %d с из туннеля не пришло ни одного пакета, но --kill-switch "+
					"держит маршрут: трафик наружу НЕ идёт", name, int(guardTrial.Seconds()))
				continue
			}
			tun.DefaultRouteDown(name)
			state, retryAfter = stWait, now+guardBackoff.Milliseconds()
			lastQuiet = now
			c.logf("ВНИМАНИЕ: хаб отвечает на служебные кадры, но за %d с не вернул НИ ОДНОГО "+
				"пакета — похоже, он не пересылает трафик. Маршрут по умолчанию возвращён "+
				"физическому интерфейсу, сеть работает как обычно. Следующая попытка через %d с "+
				"(--kill-switch запрещает такой возврат)",
				int(guardTrial.Seconds()), int(guardBackoff.Seconds()))

		case stOK:
			if rx > rxAt {
				rxAt, txAt, okSince = rx, tx, now
				continue
			}
			// Тишина считается ТОЛЬКО при активной отправке: молчание на покое — это покой.
			if tx == txAt || now-okSince < guardStall.Milliseconds() {
				if tx == txAt {
					okSince = now
				}
				continue
			}
			if c.opt.KillSwitch {
				if now-lastQuiet >= guardQuiet.Milliseconds() {
					c.logf("туннель молчит %d с, но --kill-switch держит маршрут: трафик наружу "+
						"НЕ идёт", (now-okSince)/1000)
					lastQuiet = now
				}
				continue
			}
			tun.DefaultRouteDown(name)
			state, retryAfter = stWait, now+guardBackoff.Milliseconds()
			lastQuiet = now
			c.logf("ВНИМАНИЕ: туннель перестал возвращать пакеты (%d с) — маршрут по умолчанию "+
				"возвращён физическому интерфейсу, трафик пошёл ОТКРЫТО", (now-okSince)/1000)
		}
	}
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

// Шаг повтора подключения.
//
// БЫЛО ПЯТЬ СЕКУНД ПОСТОЯННО, и это плохо в обе стороны сразу. Когда сеть на месте и соединение
// оборвалось по своей причине (смена ключей, потеря пути, перезапуск хаба), пять секунд молчания
// туннеля — очень много: восстановиться можно за один круг обмена. А когда сети нет вовсе, повтор
// раз в пять секунд — это долбёж в пустоту, который на роутере ещё и будит модем.
//
// Поэтому шаг растёт: четверть секунды, потом вдвое, до пяти секунд. И сбрасывается он не по
// таймеру, а по двум событиям, каждое из которых означает «условия изменились»: соединение прожило
// дольше redialReset (значит подключаться получается) или сеть сменилась (значит прошлая неудача про
// новую сеть ничего не говорит).
const (
	redialMin   = 250 * time.Millisecond
	redialMax   = 5 * time.Second
	redialReset = 10 * time.Second
)

// worker — одно поддельное соединение к хабу от подъёма до отмены.
func (c *Client) worker(ctx context.Context, id int, dev tun.Device, devName string) {
	wait := redialMin
	for ctx.Err() == nil {
		// Подписка берётся ДО попытки: иначе смена сети, случившаяся во время подключения,
		// осталась бы незамеченной и мы прождали бы полный шаг.
		changed := c.netChanged()
		began := time.Now()
		var err error
		if c.opt.Stream {
			err = c.streamSession(ctx, id, dev)
		} else {
			err = c.session(ctx, id, dev, devName)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			c.logf("соединение %d: %v", id, err)
		}
		if time.Since(began) >= redialReset {
			wait = redialMin
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
			wait = redialMin
		case <-time.After(wait):
			if wait *= 2; wait > redialMax {
				wait = redialMax
			}
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

	// ---- пачки и сборка разрезанных записей ----
	//
	// reasm принадлежит горутине приёма, batchMax и coolUntil — читаются отправкой и правятся
	// горутиной времени по обратной связи. Величины целые и меняются раз в секунды, поэтому
	// согласовывать их сложнее, чем стоит: худшее, что даст расхождение на такт, — одна запись,
	// собранная не с тем размером пачки.
	reasm     wire.Reasm
	lastDrops uint64
	// batchMax — сколько кадров класть в одну запись СЕЙЧАС. Не постоянная: разрезанная запись
	// гибнет целиком при потере любого сегмента, поэтому на рваном пути пачка обязана схлопываться
	// до одного кадра. Растёт по чистой обратной связи, падает мгновенно.
	batchMax   int
	coolUntil  int64
	lastReport int64
	lastGrow   int64

	// keepNext — через сколько отправить следующий keepalive. Разное каждый раз: см. timeLoop.
	keepNext int64
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

	s := &sess{conn: conn, packs: make(chan int, 4), batchMax: 2}
	if c.opt.NoBatch {
		s.batchMax = 1
	}
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
			if errors.Is(err, link.ErrAgain) {
				// Готовность без данных бывает: фильтр на сокете отбил пакет уже после того, как
				// poll его посчитал. Это не отказ — ждём дальше.
				continue
			}
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
	// Постквантовый ключ в Hello — то, что делает его браузерного размера (1759 байт против 537).
	// В режиме совместимости его нет: хаб на C собирать Hello из двух сегментов не умеет. Само
	// рукопожатие — общее с режимом потока: см. doClientHandshake. Здесь только рамка поддельного
	// TCP: Hello режется на сегменты (сегмент — MTU туннеля плюс накладные минус заголовки IP/TCP),
	// а ответ собирается из принятых сегментов.
	t := &fakeHello{conn: conn, buf: buf, ctx: ctx,
		deadline: time.Now().Add(5 * time.Second),
		maxSeg:   maxSegCeil}
	hres, err := c.doClientHandshake(hs, t, mtuSay, id, !c.opt.NoBatch)
	if err != nil {
		return err
	}
	s.tx, s.rx = hres.tx, hres.rx
	// Ключи закрываются вместе с сессией: за ядерным движком шифра стоят дескрипторы, и соединение,
	// ушедшее без этого, теряет их навсегда — а переподключений за сутки набегает много.
	defer func() { s.tx.Close(); s.rx.Close() }()

	// СОГЛАСОВАНИЕ MTU, ступень первая: минимум из пределов сторон — «максимальное для обоих
	// устройств». Ступень вторая (проверка самого пути пробами) начинается ниже, потому что канал
	// у обоих может быть шире, чем путь между ними.
	peerMTU := int(hres.peer.MTU)
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
	err = c.timeLoop(sctx, id, s, dev, devName)
	stop()
	wg.Wait()
	return err
}

// outbound: TUN → поддельный TCP.
//
// Чтение неблокирующее, поэтому пачка собирается из того, что УЖЕ пришло, и ни одного ожидания не
// добавляет: при потоковой загрузке очередь устройства не пуста и кадры набираются сами, при
// интерактивном трафике в пачке один кадр и всё работает как прежде.
//
// Отдельной горутины с каналом здесь нет намеренно: она стоила бы переключения на каждый пакет —
// замерено, 255 Мбит/с против 1582 на том же коде и том же железе.
func (c *Client) outbound(ctx context.Context, id int, s *sess, dev tun.Device) {
	row := make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag)
	scratch := make([]byte, contLen)
	// Кадры пачки лежат в одной плоской памяти: она копируется в запись при сборке, поэтому
	// отдельные буферы нужны только до этого момента.
	slab := make([]byte, wire.BatchFramesMax*wire.MTUDefault)
	frames := make([][]byte, 0, wire.BatchFramesMax)
	for ctx.Err() == nil {
		ok, err := dev.WaitRead(200 * time.Millisecond)
		if err != nil {
			if ctx.Err() == nil {
				c.logf("соединение %d: ожидание устройства: %v", id, err)
			}
			return
		}
		if !ok {
			continue
		}
		mtu := int(c.mtuNow.Load())
		max := s.batchMax
		if nowMS() < s.coolUntil {
			max = 1
		}
		frames = frames[:0]
		used, total := 0, wire.BatchHdr
		for len(frames) < max {
			// Проверка ДО чтения: прочитанный пакет девать некуда, если он не влезет в запись, а
			// откладывать его до следующего круга значило бы менять порядок пакетов в потоке.
			if len(frames) > 0 && total+2+mtu > wire.MaxPlain {
				break
			}
			n, err := dev.Read(slab[used : used+wire.MTUDefault])
			if errors.Is(err, tun.ErrAgain) {
				break
			}
			if err != nil {
				if ctx.Err() == nil {
					c.logf("соединение %d: чтение устройства: %v", id, err)
				}
				return
			}
			if n <= 0 {
				break
			}
			f := slab[used : used+n]
			// Подрезка MSS в ОБОИХ направлениях, и это не перестраховка: сюда приходят SYN от
			// узлов локальной сети, а из туннеля — SYN-ACK от узлов интернета, которые объявляют
			// MSS по СВОЕМУ каналу и ничего не знают про наш.
			route.MSSClamp(f, mtu)
			frames = append(frames, f)
			used += n
			total += 2 + n
		}
		if len(frames) == 0 {
			continue
		}
		if err := c.sendFrames(s, row, scratch, frames, mtu); err != nil {
			c.stats.dropped.Add(uint64(len(frames)))
			if errors.Is(err, link.ErrDead) {
				return
			}
			// Путь наружу пропал — ждать тишины незачем, ядро уже ответило прямо. Прежде такая
			// ошибка была неотличима от прочих и только растила счётчик отброшенных: при пропавшем
			// интернете клиент молотил в мёртвый сокет весь DeadMS.
			if errors.Is(err, link.ErrPathGone) {
				c.logf("соединение %d: %v — поднимаю заново, когда путь вернётся", id, err)
				return
			}
		} else {
			c.stats.txPkts.Add(uint64(len(frames)))
			for _, f := range frames {
				c.stats.txBytes.Add(uint64(len(f)))
			}
		}
		// Ретайр: смещение подошло к пределу или соединение старое. Замолчать ОБЯЗАНЫ — иначе
		// повтор nonce, то есть полная потеря защиты AEAD.
		if wire.RetireDue(s.conn.RelNext(), s.conn.Age()) {
			c.logf("соединение %d: смена ключей — поднимаю соединение заново", id)
			return
		}
	}
}

// sendFrames увозит кадры одной записью: один кадр — как есть, несколько — в контейнере.
func (c *Client) sendFrames(s *sess, row, scratch []byte, frames [][]byte, mtu int) error {
	var n int
	if len(frames) == 1 {
		n = copy(row[wire.HdrRoom:], frames[0])
	} else {
		n = wire.BatchBuild(row[wire.HdrRoom:], frames)
		if n == 0 {
			return fmt.Errorf("пачка не собралась")
		}
	}
	// Сегмент не больше того, что несёт путь: MTU туннеля плюс наши же накладные минус заголовки
	// IP и TCP. Ровно это число согласовано пробами, и превышать его нельзя. Не больше maxSegCeil:
	// mtu зажат потолком на всех входах (clampMTU), из того же потолка выведен и буфер продолжения.
	maxSeg := mtu + wire.Overhead - 40
	rec := row[wire.HdrRoom-wire.RecHdr : wire.HdrRoom]
	return s.conn.SendRecord(row, wire.RecHdr+n+wire.Tag, maxSeg, scratch, func(rel uint32) error {
		if err := wire.RecBuild(rec, n+wire.Tag); err != nil {
			return err
		}
		_, err := s.tx.Seal(row[wire.HdrRoom:wire.HdrRoom+n+wire.Tag], n, rec, uint64(rel))
		return err
	})
}

// sendFrame шифрует кадр открытого текста, лежащий по row[wire.HdrRoom:], и отправляет его.
//
// Шифрование идёт ВНУТРИ SendData, под тем же замком, что выдаёт смещение: см. объяснение там.
// Раздельно это уже было сделано и оказалось повтором nonce при двух отправляющих горутинах.
//
// Служебные кадры (проба, эхо, итог) уходят тем же путём, что данные: у них нет своего канала, и
// это нарочно — иначе появился бы второй путь на проводе, который DPI различал бы по размеру и
// ритму.
func (c *Client) sendFrame(s *sess, row []byte, n int) error {
	rec := row[wire.HdrRoom-wire.RecHdr : wire.HdrRoom]
	return s.conn.SendData(row, wire.RecHdr+n+wire.Tag, func(rel uint32) error {
		if err := wire.RecBuild(rec, n+wire.Tag); err != nil {
			return err
		}
		_, err := s.tx.Seal(row[wire.HdrRoom:wire.HdrRoom+n+wire.Tag], n, rec, uint64(rel))
		return err
	})
}

// inbound: поддельный TCP → TUN.
func (c *Client) inbound(ctx context.Context, id int, s *sess, dev tun.Device, devName string) {
	// RowRX, а не Row: в сырой сокет приходит склеенное GRO, и чтение в канальный предел обрезало
	// бы такой пакет вместе с записями, которые в нём лежат (см. wire.RowRX).
	buf := make([]byte, wire.RowRX)
	isn := s.conn.ISNRX()
	for ctx.Err() == nil {
		ok, err := s.conn.WaitRead(200 * time.Millisecond)
		if err != nil {
			return
		}
		if !ok {
			// Ожидание истекло, значит всплеск точно кончился: отдаём ядру то, что накопила
			// разгрузка сегментации. Обычно к этой строке отдавать уже нечего — сброс произошёл на
			// ErrAgain ниже, — но оставить пакет в буфере на двести миллисекунд нельзя ни при каком
			// стечении обстоятельств.
			if err := dev.Flush(); err != nil {
				c.stats.dropped.Add(1)
			}
			continue
		}
		// ДОБИРАЕМ ВСЁ, ЧТО УЖЕ ПРИШЛО, ОДНИМ ЗАХОДОМ, и это два выигрыша сразу.
		//
		// Первый: сокет неблокирующий, поэтому «пришло ли ещё» узнаётся самим чтением, а не
		// отдельным poll перед каждым пакетом — на полутора гигабитах это пятьдесят тысяч
		// системных вызовов в секунду, снятых начисто.
		//
		// Второй: пока заход не кончился, записанные в устройство пакеты копятся в супер-кадр
		// разгрузки, и в ядро они уедут ОДНИМ вызовом вместо сорока пяти. Отдаётся накопленное
		// ровно на границе всплеска (ErrAgain), поэтому задержки это не добавляет.
		for i := 0; i < 64; i++ {
			if !c.inSeg(s, id, buf, isn, dev, devName) {
				break
			}
		}
		if err := dev.Flush(); err != nil {
			c.stats.dropped.Add(1)
		}
	}
}

// inSeg разбирает ОДИН принятый сегмент. false означает «больше сегментов сейчас нет либо
// соединение пора поднимать заново» — то есть выход из захода.
func (c *Client) inSeg(s *sess, id int, buf []byte, isn uint32, dev tun.Device, devName string) bool {
	seg, mine, err := s.conn.Recv(buf)
	if err != nil {
		// ErrAgain — очередь пуста, всплеск кончился. Любая другая ошибка чтения означает, что
		// сокет больше не работает: там выходить надо не из захода, а из соединения, и это делает
		// вызывающий по отмене общего контекста.
		return false
	}
	if !mine {
		return true
	}
	data, err := s.conn.OnSeg(&seg)
	if err != nil {
		c.logf("соединение %d: %v", id, err)
		return false
	}
	if !data {
		return true
	}
	// Сборка записи, которая могла быть разрезана между сегментами. Она же служит предфильтром:
	// сегмент, не начинающийся с заголовка записи и не продолжающий начатую, отбрасывается до
	// всякой криптографии.
	//
	// ЦИКЛОМ по всей нагрузке, а не по одной записи: ядро отдаёт в сырой сокет склеенное GRO, и
	// записей в одной нагрузке бывает несколько (см. Reasm.Feed).
	s.reasm.FeedAll(seg.Seq, isn, seg.Payload, func(body, hdr []byte, rel uint32) {
		if !s.win.Check(rel) {
			return
		}
		// AAD — заголовок записи, как в TLS 1.3: для разрезанной это байты ПЕРВОГО сегмента, то
		// есть у обеих сторон одни и те же.
		pt, err := s.rx.Open(body, hdr, uint64(rel))
		if err != nil {
			return
		}
		// Коммит окна ТОЛЬКО после сошедшегося тега: иначе подделанный пакет с далёким смещением
		// выбил бы из окна весь честный поток.
		s.win.Commit(rel)
		if len(pt) > 0 && pt[0] == wire.CtlBatch {
			if !wire.BatchIter(pt, func(f []byte) { c.onFrame(s, id, f, dev) }) {
				c.stats.dropped.Add(1)
			}
			return
		}
		c.onFrame(s, id, pt, dev)
	})
	return true
}

// onFrame — один кадр открытого текста: внутренний пакет или служебное сообщение.
func (c *Client) onFrame(s *sess, id int, pt []byte, dev tun.Device) {
	// Живость отмечается на ЛЮБОМ разобранном кадре, включая служебный. Это и есть
	// доказательство, которого ждёт сторож маршрута: рукопожатие доказывает, что хаб нас узнал,
	// и ровно ничего не говорит о том, повезёт ли он трафик. Разница не теоретическая — стенд
	// показал хаб, который принимает и подтверждает каждый наш сегмент, а обратно не шлёт ни
	// байта; по рукопожатию он выглядел работающим.
	c.stats.lastRx.Store(nowMS())
	switch wire.FrameKind(pt) {
	case wire.KindIPv4, wire.KindIPv6:
		route.MSSClamp(pt, int(c.mtuNow.Load()))
		if _, err := dev.Write(pt); err != nil {
			c.stats.dropped.Add(1)
			return
		}
		c.stats.rxPkts.Add(1)
		c.stats.rxBytes.Add(uint64(len(pt)))
	case wire.KindCtl:
		c.onCtlFrame(s, id, pt)
	}
	// keepalive молча учтён: он уже обновил время последнего приёма.
}

// onCtlFrame — служебные кадры от хаба.
func (c *Client) onCtlFrame(s *sess, id int, pt []byte) {
	if acked := wire.PackSize(pt); acked > 0 {
		select {
		case s.packs <- acked:
		default:
		}
		return
	}
	// Хаб сообщает, что у него не собираются наши записи: значит путь рвёт сегменты, и пачку надо
	// схлопнуть немедленно. Без этой обратной связи одна потеря стоила бы всей пачки, и на рваном
	// пути пачки делали бы хуже, а не лучше.
	if n := wire.LossValue(pt); n > 0 {
		s.batchMax = 1
		s.coolUntil = nowMS() + reasmCooldownMS
		c.logf("соединение %d: хаб не собрал %d записей — везу по одному кадру", id, n)
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
//
// Он же следит за поколением сети: соединение, открытое в прежней сети, после смены адреса выхода
// не годится вовсе — сокет ПОДКЛЮЧЁН, то есть адрес источника закреплён при открытии. Ждать, пока
// это выяснится по тишине или по ошибке отправки, незачем: ядро уже сказало, что сеть другая.
func (c *Client) timeLoop(ctx context.Context, id int, s *sess, dev tun.Device, devName string) error {
	gen := c.netGen.Load()
	t := time.NewTicker(link.TickMS * time.Millisecond)
	defer t.Stop()
	keepalive := int64(c.opt.Conf.Peers[0].Keepalive) * 1000
	if keepalive > 0 && s.keepNext == 0 {
		s.keepNext = keepalive*8/10 + rand.Int64N(keepalive*4/10+1)
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case acked := <-s.packs:
			c.onPack(s, id, acked, dev, devName)
			continue
		case <-t.C:
		}
		// Сеть стала другой: поднимаемся заново немедленно. Проверка стоит ПЕРЕД Tick, потому что
		// после смены адреса Tick ничего полезного не скажет — он ждёт тишины, которая тут уже
		// известна заранее.
		if c.netGen.Load() != gen {
			return errors.New("сеть изменилась — поднимаю соединение заново")
		}
		if err := s.conn.Tick(); err != nil {
			return fmt.Errorf("путь молчит %d мс при активной отправке — поднимаю заново",
				link.DeadMS)
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

		// Обратная связь по сборке: если у НАС не собираются записи, надо сказать об этом той
		// стороне — она одна может уменьшить пачку. Молча терпеть значило бы, что на рваном пути
		// пачки делают хуже, а не лучше, и никто об этом не узнает.
		if drops := s.reasm.Dropped; drops > s.lastDrops && now-s.lastReport >= reasmReportMS {
			frame := make([]byte, wire.HdrRoom+8+wire.Tag)
			if n := wire.LossBuild(frame[wire.HdrRoom:wire.HdrRoom+8], int(drops-s.lastDrops)); n > 0 {
				if c.sendFrame(s, frame, n) == nil {
					s.lastDrops = drops
					s.lastReport = now
				}
			}
		}
		// Рост пачки на чистом пути: медленно вверх, мгновенно вниз (см. onCtlFrame).
		if !c.opt.NoBatch && now >= s.coolUntil && now-s.lastGrow >= reasmGrowMS &&
			s.batchMax < wire.BatchFramesMax {
			s.batchMax *= 2
			if s.batchMax > wire.BatchFramesMax {
				s.batchMax = wire.BatchFramesMax
			}
			s.lastGrow = now
		}

		// Keepalive: пустая запись. Пир за NAT обязан поддерживать отображение живым, потому что
		// дозвониться до него хаб не может.
		//
		// ИНТЕРВАЛ С РАЗБРОСОМ, а не ровный. Ровный интервал — это признак сам по себе: пакет
		// одного и того же размера ровно каждые пятнадцать секунд не встречается ни в одном
		// браузерном соединении, и находится он простым подсчётом пауз между мелкими пакетами.
		// Разброс ±20% ничего не стоит и делает такой подсчёт бессмысленным.
		if keepalive > 0 && s.conn.SinceTX() >= s.keepNext {
			frame := make([]byte, wire.HdrRoom+wire.Tag)
			_ = c.sendFrame(s, frame, 0)
			s.keepNext = keepalive*8/10 + rand.Int64N(keepalive*4/10+1)
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

// devMTU — рабочий MTU по устройству, которым владеет КТО-ТО ДРУГОЙ (служба системы, графический
// клиент). Своего мы там не ставим: адрес, MTU и маршруты заданы не нами.
//
// Значение ЗАЖИМАЕТСЯ потолком, а не просто сопровождается предупреждением. Предупреждение здесь
// было и раньше, и оно честное: пакеты действительно пропадают. Но пропадали они не потому, что
// устройство отдаёт слишком крупные кадры (их режет сам путь), а потому, что по этому числу
// считался предельный сегмент, под который не хватало буфера продолжения записи, — то есть КАЖДАЯ
// разрезаемая запись отваливалась у нас же, не дойдя до провода. Настройку чужого устройства мы
// поправить не вправе, а собственный предел обязаны соблюдать сами.
func (c *Client) devMTU(name string, got int) int {
	mtu := clampMTU(got)
	c.logf("%s: устройством владеет кто-то другой, MTU %d (накладные %d)", name, got, wire.Overhead)
	if mtu != got {
		c.logf("ВНИМАНИЕ: MTU %d больше предела %d для канала 1500 — большие пакеты будут "+
			"пропадать; работаю на %d, поставьте столько же в настройках устройства",
			got, mtuCeil, mtu)
	}
	return mtu
}

// applyMTU ставит устройству новый MTU. Значение, заданное человеком в конфигурации, никогда не
// превышается: если он написал 1380, мы не поставим 1431, даже если путь его несёт.
func (c *Client) applyMTU(dev tun.Device, devName string, mtu int, why string) {
	// Потолок и здесь: applyMTU — единственная дверь, через которую значение попадает и на
	// устройство, и в mtuNow, откуда его берёт отправка. Согласование выше него не поднимается по
	// построению, но проверка стоит там, где значение применяется, а не там, где считается.
	mtu = clampMTU(mtu)
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
