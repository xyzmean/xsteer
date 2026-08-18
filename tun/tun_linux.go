//go:build linux

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"unsafe"

	"golang.org/x/sys/unix"
)

type linuxDev struct {
	f    *os.File
	name string
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
func Open(name string) (Device, error) { return openOne(name, false) }

func openOne(name string, multiQueue bool) (Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
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
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, f.Fd(), uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req))); e != 0 {
		f.Close()
		return nil, fmt.Errorf("%w: TUNSETIFF %s: %v", ErrNoDevice, name, e)
	}
	got := string(req.name[:])
	if i := indexZero(req.name[:]); i >= 0 {
		got = string(req.name[:i])
	}
	return &linuxDev{f: f, name: got}, nil
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
func OpenQueues(name string, n int) ([]Device, error) {
	if n < 1 {
		n = 1
	}
	var out []Device
	for i := 0; i < n; i++ {
		d, err := openOne(name, n > 1)
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

func (d *linuxDev) Read(p []byte) (int, error)  { return d.f.Read(p) }
func (d *linuxDev) Write(p []byte) (int, error) { return d.f.Write(p) }
func (d *linuxDev) Name() string                { return d.name }
func (d *linuxDev) Close() error                { return d.f.Close() }

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

// AddRoute направляет префикс в устройство. Нужен, чтобы трафик вообще попадал в туннель: без
// маршрута устройство поднято и пусто, и это самый частый вопрос «почему ничего не идёт».
func AddRoute(name, cidr string) error {
	return run("ip", "route", "replace", cidr, "dev", name)
}

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
