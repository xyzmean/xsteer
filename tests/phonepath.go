//go:build ignore

// phonepath — пир, поднятый РОВНО ТАК ЖЕ, как его поднимает телефон на Android.
//
// ЗАЧЕМ ОТДЕЛЬНАЯ ПРОГРАММА, А НЕ КЛЮЧ К xsteer. Жалоба «на телефоне около ста мегабит» не
// воспроизводится обычным `xsteer up`: тот открывает устройство сам, с IFF_VNET_HDR, то есть с
// разгрузкой сегментации, и читает-пишет супер-кадры. На Android устройство открывает система
// (VpnService), флага IFF_VNET_HDR у него нет и поставить его некому: он задаётся при создании.
// Значит путь данных там другой — один пакет, одно чтение, один пакет, одна запись, — и мерить
// надо именно его. Здесь дескриптор открывается без IFF_VNET_HDR и отдаётся клиенту готовым,
// через tun.FromFD, то есть тем же входом, которым пользуется mobile.Tunnel.StartFD.
//
// НАСТРОЙКИ КЛИЕНТА ПОВТОРЯЮТ mobile/mobile.go ЗНАЧЕНИЕ В ЗНАЧЕНИЕ (Managed, Routes, Stream,
// NoNetWatch, AESPreferred). Если они там изменятся, здесь надо изменить тоже — иначе стенд
// начнёт мерить не то, на что жалуются. Единственное, что здесь сделано отдельно: число
// соединений задаётся ключом, потому что ради ответа «сколько их должно быть» стенд и написан.
//
// Запускается из tests/phone.sh; руками — так:
//
//	go run tests/phonepath.go --conf a.conf --dev xsp0 --addr 10.79.0.2/24 \
//	    --route 10.79.0.0/24 --stream-port 443 --conns 1
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/xyzmean/xsteer/client"
	"github.com/xyzmean/xsteer/conf"
	"github.com/xyzmean/xsteer/tun"
	"golang.org/x/sys/unix"
)

func main() {
	var (
		confPath  = flag.String("conf", "", "файл настройки пира")
		devName   = flag.String("dev", "xsp0", "имя устройства")
		addr      = flag.String("addr", "", "адрес с маской на устройстве, например 10.79.0.2/24")
		route     = flag.String("route", "", "что направить в устройство, через запятую")
		mtu       = flag.Int("mtu", 1439, "MTU устройства")
		conns     = flag.Int("conns", 1, "соединений к хабу")
		strPort   = flag.Int("stream-port", 0, "порт хаба в режиме потока")
		txqueue   = flag.Int("txqueue", 500, "длина очереди устройства (у VpnService она ядерная, 500)")
		vnet      = flag.Bool("vnet", false, "открыть устройство САМИМ, с разгрузкой сегментации — это НЕ телефонный путь, а образец для сравнения")
		pprofAddr = flag.String("pprof", "", "адрес для профиля (например 127.0.0.1:6060)")
	)
	flag.Parse()
	if err := run(*confPath, *devName, *addr, *route, *pprofAddr, *mtu, *conns, *strPort, *txqueue, *vnet); err != nil {
		fmt.Fprintln(os.Stderr, "phonepath:", err)
		os.Exit(1)
	}
}

func run(confPath, devName, addr, route, pprofAddr string, mtu, conns, strPort, txqueue int, vnet bool) error {
	if confPath == "" || addr == "" {
		return fmt.Errorf("нужны --conf и --addr")
	}
	dev, got, err := openDev(devName, mtu, vnet)
	if err != nil {
		return err
	}
	defer dev.Close()
	// Устройство настраиваем СВОИМИ руками и до подъёма клиента: клиент поднимается с Managed,
	// то есть считает, что адрес, MTU и очередь ему задал владелец. На телефоне владелец — сама
	// система (VpnService.Builder), здесь — эта программа.
	for _, args := range [][]string{
		{"link", "set", "dev", got, "up", "mtu", fmt.Sprint(mtu), "txqueuelen", fmt.Sprint(txqueue)},
		{"addr", "add", addr, "dev", got},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("ip %s: %v: %s", strings.Join(args, " "), err, out)
		}
	}
	for _, r := range strings.Split(route, ",") {
		if r = strings.TrimSpace(r); r == "" {
			continue
		}
		// Уже существующий маршрут — не ошибка: адрес с маской заводит связанный маршрут сам, и
		// просьба направить ту же сеть в то же устройство ничего не меняет.
		if out, err := exec.Command("ip", "route", "add", r, "dev", got).CombinedOutput(); err != nil &&
			!strings.Contains(string(out), "File exists") {
			return fmt.Errorf("ip route add %s: %v: %s", r, err, out)
		}
	}

	c, s, _, err := conf.LoadAny(confPath, conf.RoleSpoke)
	if err != nil {
		return err
	}
	defer s.Wipe()

	if pprofAddr != "" {
		go func() { fmt.Fprintln(os.Stderr, "pprof:", http.ListenAndServe(pprofAddr, nil)) }()
	}

	opt := client.Options{
		Conf: c,
		Sec:  s,
		// Дальше — копия того, что ставит mobile/mobile.go. Менять здесь можно только вместе с ним.
		Devs:         []tun.Device{dev},
		Conns:        conns,
		Managed:      true,
		Routes:       false,
		Stream:       true,
		StreamPort:   strPort,
		NoNetWatch:   true,
		AESPreferred: true,
		Logf:         func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) },
	}
	fmt.Fprintf(os.Stderr, "phonepath: устройство %s, %s, соединений %d, MTU %d, очередь %d\n",
		got, offloadWord(dev), conns, mtu, txqueue)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		time.Sleep(4 * time.Second)
		os.Exit(0) // стенд не должен зависать на уборке: его снимают сигналом
	}()
	return client.Run(ctx, opt)
}

func offloadWord(d tun.Device) string {
	o, ok := d.(interface{ Offload() (bool, string) })
	if !ok {
		return "разгрузки нет"
	}
	on, why := o.Offload()
	if on {
		return "разгрузка ВКЛЮЧЕНА"
	}
	return "разгрузки нет (" + why + ")"
}

// openDev заводит устройство одним из двух способов.
//
// vnet == false — ТЕЛЕФОННЫЙ путь: дескриптор открыт здесь, без IFF_VNET_HDR, и отдан клиенту
// готовым через tun.FromFD. Ровно это делает Android: набор флагов задаётся один раз, при
// создании, и добавить IFF_VNET_HDR к чужому дескриптору нельзя — поэтому у устройства от
// VpnService разгрузки сегментации нет и быть не может.
//
// vnet == true — образец для сравнения: устройство открывает сам пакет tun, с разгрузкой. Так
// работает десктоп и роутер, и разница между двумя прогонами и есть цена отсутствия разгрузки.
func openDev(name string, mtu int, vnet bool) (tun.Device, string, error) {
	if vnet {
		d, err := tun.Open(name)
		if err != nil {
			return nil, "", err
		}
		return d, d.Name(), nil
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", fmt.Errorf("/dev/net/tun: %w", err)
	}
	var req ifreq
	copy(req.name[:15], name)
	req.flags = unix.IFF_TUN | unix.IFF_NO_PI
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&req))); e != 0 {
		unix.Close(fd)
		return nil, "", fmt.Errorf("TUNSETIFF %s: %v", name, e)
	}
	got := name
	for i, b := range req.name {
		if b == 0 {
			got = string(req.name[:i])
			break
		}
	}
	d, err := tun.FromFD(fd, got, mtu)
	if err != nil {
		unix.Close(fd)
		return nil, "", err
	}
	return d, got, nil
}

type ifreq struct {
	name  [16]byte
	flags uint16
	_     [22]byte
}
