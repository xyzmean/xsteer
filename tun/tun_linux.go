//go:build linux

package tun

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// linuxDev держит СЫРОЙ дескриптор, а не os.File, и это не мелочь.
//
// os.File отдаёт дескриптор сетевому опросчику Go, и тогда Read блокируется до появления данных —
// узнать «сейчас пусто» становится нечем, а без этого нельзя собрать пачку из того, что уже
// пришло, не заводя отдельной горутины с каналом. Канал стоил шестикратного падения скорости
// (255 Мбит/с против 1582 на том же железе): на каждый пакет приходилось переключение горутин.
type linuxDev struct {
	fd   int
	name string
	// off — разгрузка сегментации, если ядро её приняло. nil означает прежний путь: один пакет —
	// одно чтение, один пакет — одна запись. См. offload_linux.go.
	off    *offload
	offWhy string // почему разгрузки нет — для строки при подъёме
}

type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}

// Open создаёт (или открывает существующее) устройство TUN.
//
// existing == true означает «устройством владеет кто-то другой»: адрес, MTU и правила ему уже
// задал он, и трогать их нельзя — две стороны, настраивающие одно устройство, это гонка, в которой
// проигрывает та, что настроила первой, а заметно это будет как «MTU иногда не тот».
func Open(name string) (Device, error) { return openOne(name, false, true) }

// OpenPlain — устройство БЕЗ разгрузки сегментации. Нужно ровно двум: ключу командной строки, если
// разгрузка однажды окажется виновата, и тесту, который проверяет прежний путь.
func OpenPlain(name string) (Device, error) { return openOne(name, false, false) }

func openOne(name string, multiQueue, offload bool) (Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: /dev/net/tun (%v) — на Linux нужен модуль tun и права root",
			ErrNoDevice, err)
	}
	var req ifreq
	copy(req.name[:15], name)
	// IFF_NO_PI: без него перед каждым пакетом едут четыре байта заголовка платформы, и путь
	// данных пришлось бы учить их отрезать — то есть знание об устройстве утекло бы наружу.
	req.flags = unix.IFF_TUN | unix.IFF_NO_PI
	if multiQueue {
		req.flags |= unix.IFF_MULTI_QUEUE
	}
	// IFF_VNET_HDR запрашивается В ТОМ ЖЕ TUNSETIFF, а не отдельным вызовом: сменить набор флагов у
	// уже созданного устройства ядро не даёт, и «включим потом» означало бы закрыть и открыть
	// устройство заново — то есть на миг снять его вместе с маршрутами.
	//
	// Проверяем, умеет ли ядро, ДО запроса: TUNGETFEATURES отвечает набором поддерживаемых флагов, и
	// без этой проверки старое ядро отказало бы на TUNSETIFF целиком, то есть разгрузка стоила бы
	// полной невозможности поднять туннель.
	if offload && kernelHasVnetHdr(fd) {
		req.flags |= unix.IFF_VNET_HDR
	} else {
		offload = false
	}
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req))); e != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("%w: TUNSETIFF %s: %v", ErrNoDevice, name, e)
	}
	got := string(req.name[:])
	if i := indexZero(req.name[:]); i >= 0 {
		got = string(req.name[:i])
	}
	// Имя, которое вернуло ядро, обязано совпасть с запрошенным. Не совпадает оно ровно в одном
	// случае: имя длиннее 15 значащих символов, и лишнее обрезано выше нашим же copy. Дальше
	// работать с полученным именем — значит поднять туннель на устройстве, о котором никто не
	// просил: маршруты, правила и (на роутере) зона firewall заведены управляющим слоем по имени
	// из настроек, и они остались бы на имени, которого нет. Тишина при этом полная — в
	// реализации на C та же ошибка давала «интерфейс поднят, трафика нет» (I-107).
	//
	// Пустое имя — не тот случай: тогда имя выбирает ядро, и другого источника правды нет.
	// Оба вызывающих (client, hub) подставляют своё умолчание, так что сюда пустое не доходит.
	if name != "" && got != name {
		unix.Close(fd)
		return nil, fmt.Errorf("%w: ядро создало устройство %q вместо %q — имя длиннее предела "+
			"в 15 значащих символов; задайте короче", ErrNoDevice, got, name)
	}
	d := &linuxDev{fd: fd, name: got}
	if offload {
		// Отказ здесь НЕ отказ подъёма: без разгрузки туннель работает прежним путём, только
		// медленнее. Причина отказа названа вызывающему через OffloadWhy, чтобы «почему медленно»
		// не приходилось выяснять догадками.
		off, err := tryOffload(fd)
		if err != nil {
			d.offWhy = err.Error()
		} else {
			d.off = off
		}
	} else {
		d.offWhy = "не запрошена"
	}
	return d, nil
}

// kernelHasVnetHdr — умеет ли ядро метаданные virtio на этом устройстве.
func kernelHasVnetHdr(fd int) bool {
	var feat uint32
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNGETFEATURES),
		uintptr(unsafe.Pointer(&feat))); e != 0 {
		return false
	}
	return feat&unix.IFF_VNET_HDR != 0
}

// OpenQueues открывает устройство с НЕСКОЛЬКИМИ очередями: по одной на воркера.
//
// Зачем это, а не N горутин, читающих один дескриптор. Ядро раскладывает пакеты по очередям
// симметричным хешем потока, поэтому обе половины одного соединения TCP всегда достаются одному
// воркеру. Читай все горутины один дескриптор — пакеты одного потока разъезжались бы по разным
// соединениям к хабу и приезжали бы переставленными, а для получателя переупорядочивание выглядит
// как потери и рушит скорость. Ровно то же делает движок на C.
//
// Если ядро не умеет многоочерёдность (IFF_MULTI_QUEUE появился в 3.8), возвращаем одну очередь:
// туннель будет работать одним воркером, и это лучше отказа.
func OpenQueues(name string, n int) ([]Device, error) { return openQueues(name, n, true) }

// OpenQueuesPlain — то же без разгрузки сегментации.
func OpenQueuesPlain(name string, n int) ([]Device, error) { return openQueues(name, n, false) }

func openQueues(name string, n int, offload bool) ([]Device, error) {
	if n < 1 {
		n = 1
	}
	var out []Device
	for i := 0; i < n; i++ {
		d, err := openOne(name, n > 1, offload)
		if err != nil {
			if i == 0 {
				return nil, err
			}
			// Часть очередей не открылась — работаем меньшим числом. Уронить туннель из-за того,
			// что второе ядро занять не удалось, было бы хуже, чем занять одно.
			break
		}
		out = append(out, d)
	}
	return out, nil
}

func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

func (d *linuxDev) Read(p []byte) (int, error) {
	if d.off != nil {
		return d.off.read(p)
	}
	return readFD(d.fd, p)
}

// readFD — чтение дескриптора устройства. Отдельной функцией, потому что читает и путь без
// разгрузки, и разбор супер-кадров.
func readFD(fd int, p []byte) (int, error) {
	for {
		n, err := unix.Read(fd, p)
		switch err {
		case nil:
			return n, nil
		case unix.EINTR:
			continue
		case unix.EAGAIN:
			return 0, ErrAgain
		default:
			return 0, err
		}
	}
}

func (d *linuxDev) Write(p []byte) (int, error) {
	if d.off != nil {
		return d.off.write(p)
	}
	return writeFD(d.fd, p)
}

// Flush отдаёт ядру то, что накопила разгрузка. Без разгрузки — ничего не делает: писать уже
// нечего, каждый пакет ушёл своим вызовом.
func (d *linuxDev) Flush() error {
	if d.off == nil {
		return nil
	}
	return d.off.Flush()
}

// Offload — работает ли разгрузка сегментации, и если нет — почему. Печатается при подъёме: разница
// в скорости здесь измеряется разами, и знать её надо ДО замеров, а не после.
func (d *linuxDev) Offload() (bool, string) {
	if d.off != nil {
		return true, ""
	}
	return false, d.offWhy
}

func writeFD(fd int, p []byte) (int, error) {
	for {
		n, err := unix.Write(fd, p)
		if err == unix.EINTR {
			continue
		}
		// EAGAIN здесь означает, что ядро прямо сейчас не приняло пакет: он потерян, и это
		// нормальная перегрузка, а не отказ — повторять смысла нет, внутренний TCP разберётся.
		//
		// Прежде здесь было написано «переполненную очередь устройства», и это неверно: запись в
		// TUN идёт в ПРИЁМНЫЙ путь ядра и в txqueuelen не упирается. Проба на ядре 6.8 (та же, что
		// в движке на C, — I-116): 200 000 неблокирующих записей, ноль EAGAIN, ноль rx_dropped.
		// Про очередь устройства — обратное направление и константа TxQueueLen, см. tun.go.
		if err == unix.EAGAIN {
			return 0, ErrAgain
		}
		return n, err
	}
}

func (d *linuxDev) WaitRead(timeout time.Duration) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(d.fd), Events: unix.POLLIN}}
	ms := int(timeout / time.Millisecond)
	for {
		n, err := unix.Poll(fds, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, err
		}
		return n > 0, nil
	}
}

func (d *linuxDev) Name() string { return d.name }
func (d *linuxDev) Close() error { return unix.Close(d.fd) }

// SetMTU и SetAddr сделаны через `ip`, а не через netlink.
//
// Причина не в лени: netlink здесь означал бы свою сборку сообщений RTM_NEWADDR и RTM_SETLINK,
// то есть сотню строк, которые надо и написать, и проверить. Команда `ip` есть на любой системе,
// где вообще есть TUN, её поведение видно человеку в журнале, и ровно так же это делает движок на
// C. Цена — запуск процесса на КАЖДУЮ смену MTU, а она случается раз в минуты.
func (d *linuxDev) SetMTU(mtu int) error {
	return run("ip", "link", "set", "dev", d.name, "mtu", strconv.Itoa(mtu), "up")
}

// SetAddr задаёт адрес внутри туннеля.
func SetAddr(name, cidr string) error {
	return run("ip", "addr", "replace", cidr, "dev", name)
}

// SetTxQueueLen просит у ядра очередь устройства длиной n пакетов.
//
// Стоит рядом с SetAddr и SetMTU, потому что это третья команда подъёма — ровно так же устроен
// движок на C (tun_bring_up: адрес, up, txqueuelen). Зачем нужна и что именно измеряется —
// в комментарии к TxQueueLen (tun.go).
//
// Отказ здесь НЕ отказ подъёма: трафик пойдёт и с ядерной очередью в 500 пакетов, потеряна будет
// только скорость на пиках. Поэтому вызывающие называют его осведомляющей строкой, а не
// предупреждением: на системах, где txqueuelen не принимают вовсе, тревожный тон означал бы
// красную строку на каждом штатном запуске.
func SetTxQueueLen(name string, n int) error {
	return run("ip", "link", "set", "dev", name, "txqueuelen", strconv.Itoa(n))
}

// AddRoute направляет префикс в устройство. Нужен, чтобы трафик вообще попадал в туннель: без
// маршрута устройство поднято и пусто, и это самый частый вопрос «почему ничего не идёт».
func AddRoute(name, cidr string) error {
	return run("ip", "route", "replace", cidr, "dev", name)
}

// SetupRoutes ставит маршруты AllowedIPs. На Linux расщепление маршрута по умолчанию и обход
// для хаба здесь не нужны: полным туннелем на роутере управляет движок steer своими таблицами
// и правилами (fwmark), а не этот клиент. Поэтому просто раскладываем префиксы как есть; аргумент
// endpoints не используется и оставлен ради единой сигнатуры с Windows.
//
// Второе возвращаемое значение — «просили полный туннель». На Windows оно означает «маршрут по
// умолчанию отложен до подтверждения», здесь — только осведомление вызывающего: маршрут уже
// поставлен как обычный префикс, и отдельного шага ему не требуется.
func SetupRoutes(name string, cidrs, endpoints []string) (bool, error) {
	_ = endpoints
	full := false
	for _, c := range cidrs {
		if err := AddRoute(name, c); err != nil {
			return full, err
		}
		if p, e := netip.ParsePrefix(strings.TrimSpace(c)); e == nil && p.Bits() == 0 && p.Addr().Is4() {
			full = true
		}
	}
	return full, nil
}

// DefaultRouteUp на Linux уже сделан в SetupRoutes: 0.0.0.0/0 ставится обычным `ip route replace`
// на устройство, и спорить с физическим маршрутом по метрикам здесь не приходится.
func DefaultRouteUp(name string) error { _ = name; return nil }

// DefaultRouteDown на Linux снимает маршрут по умолчанию с устройства. Ошибку глотаем: если
// маршрута уже нет, снимать нечего, и это не повод шуметь на выходе.
func DefaultRouteDown(name string) { _ = run("ip", "route", "del", "0.0.0.0/0", "dev", name) }

// DefaultRouteIsUp на Linux не отслеживается отдельно: маршрут ставится сразу и живёт с
// устройством.
func DefaultRouteIsUp(name string) bool { _ = name; return true }

// SetDNS на Linux не трогает /etc/resolv.conf: клиент живёт на роутере, где именами
// распоряжается dnsmasq, и переписывать его файл из-под туннеля значило бы драться с ним за
// один ресурс. Отказ назван прямо, чтобы «DNS = ...» не выглядел применённым.
func SetDNS(name string, servers []string) error {
	_ = name
	if len(servers) == 0 {
		return nil
	}
	return fmt.Errorf("DNS из конфигурации на Linux не применяется: настройте резолвер сами")
}

// TeardownRoutes на Linux снимать нечего: маршруты уходят с устройством.
func TeardownRoutes(name string) { _ = name }

// DevMTU — MTU, который сейчас стоит на устройстве.
func DevMTU(name string) int {
	b, err := os.ReadFile("/sys/class/net/" + name + "/mtu")
	if err != nil {
		return 0
	}
	v, err := strconv.Atoi(string(trimSpace(b)))
	if err != nil {
		return 0
	}
	return v
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == ' ' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func run(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %v: %s", args, err, out)
	}
	return nil
}
