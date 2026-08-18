//go:build windows

package tun

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Устройство на Windows — это Wintun: адаптер NDIS от проекта WireGuard, единственный способ
// получить в пользовательском пространстве обычный сетевой интерфейс без своего драйвера.
//
// ПОЧЕМУ ИМЕННО ОН. Своего драйвера у нас быть не может (нужен EV-сертификат и аттестация
// Microsoft), а Wintun распространяется подписанной DLL — это [единственный поддерживаемый
// способ](https://www.wintun.net/), и он же самый доверенный: тот же файл ставит WireGuard, и
// антивирусы к нему привыкли. Файл wintun.dll лежит рядом с исполняемым; без него запуск честно
// падает с указанием, чего не хватает.
//
// ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ /dev/net/tun. У Wintun не дескриптор, а КОЛЬЦЕВОЙ БУФЕР в разделяемой
// памяти: пакеты забираются указателем без копии и освобождаются обратно, а «данные появились»
// сообщается событием, а не готовностью дескриптора. Ровно поэтому в интерфейсе Device есть
// WaitRead и ErrAgain — они писались с оглядкой на эту платформу, чтобы путь данных не пришлось
// переделывать под неё.

// Размер кольца — четыре мегабайта, как у WireGuard. Больше не нужно: кольцо нужно лишь на всплеск
// между двумя нашими проходами, а не как буфер очереди.
const ringCapacity = 0x400000

type winDev struct {
	adapter *wintun.Adapter
	session wintun.Session
	name    string
	luid    winipcfg.LUID

	mu     sync.Mutex
	closed bool
}

// Реестр «имя → LUID»: настройка адреса и маршрутов на Windows идёт по LUID адаптера, а наш
// интерфейс пакета принимает имя (так устроен путь на Linux). Заводить в интерфейсе платформенный
// идентификатор значило бы протащить Windows во все вызовы; проще запомнить соответствие здесь.
var (
	luidsMu sync.Mutex
	luids   = map[string]winipcfg.LUID{}
)

// Open создаёт (или переоткрывает) адаптер.
//
// GUID выводится из имени детерминированно, а не берётся случайным: тогда повторный запуск получает
// ТОТ ЖЕ адаптер, а не плодит новый с суффиксом в имени — иначе после десятка перезапусков в системе
// остаётся десяток «xs0 #7», и человек не понимает, какой из них живой.
func Open(name string) (Device, error) {
	if name == "" {
		name = "xsteer"
	}
	guid := guidFromName(name)
	adapter, err := wintun.CreateAdapter(name, "xsteer", &guid)
	if err != nil {
		return nil, fmt.Errorf("%w: Wintun не создал адаптер %q (%v). Нужен wintun.dll рядом с "+
			"исполняемым файлом и запуск от администратора", ErrNoDevice, name, err)
	}
	session, err := adapter.StartSession(ringCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("%w: Wintun не открыл сессию: %v", ErrNoDevice, err)
	}
	d := &winDev{adapter: adapter, session: session, name: name,
		luid: winipcfg.LUID(adapter.LUID())}
	luidsMu.Lock()
	luids[name] = d.luid
	luidsMu.Unlock()
	return d, nil
}

// OpenQueues на Windows отдаёт одну очередь: у Wintun одна сессия на адаптер, и раскладка по
// воркерам делается не здесь. Клиент это умеет — он берёт столько соединений, сколько очередей.
func OpenQueues(name string, n int) ([]Device, error) {
	d, err := Open(name)
	if err != nil {
		return nil, err
	}
	return []Device{d}, nil
}

// guidFromName — устойчивый GUID из имени. Версия и вариант выставляются как у GUID версии 4, чтобы
// система не сочла его испорченным.
func guidFromName(name string) windows.GUID {
	h := sha256.Sum256([]byte("xsteer/" + name))
	var g windows.GUID
	g.Data1 = uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3])
	g.Data2 = uint16(h[4])<<8 | uint16(h[5])
	g.Data3 = uint16(h[6])<<8 | uint16(h[7])
	copy(g.Data4[:], h[8:16])
	g.Data3 = (g.Data3 & 0x0FFF) | 0x4000
	g.Data4[0] = (g.Data4[0] & 0x3F) | 0x80
	return g
}

// Read забирает один пакет из кольца. Пусто — ErrAgain: путь данных на этом перестаёт добирать
// кадры в пачку и отправляет набранное.
func (d *winDev) Read(p []byte) (int, error) {
	for {
		pkt, err := d.session.ReceivePacket()
		switch err {
		case nil:
			n := copy(p, pkt)
			d.session.ReleaseReceivePacket(pkt)
			if n < len(pkt) {
				// Пакет длиннее буфера означает, что MTU устройства больше, чем мы готовы нести;
				// молча отдать половину пакета нельзя — он не соберётся никогда.
				return 0, fmt.Errorf("пакет %d байт не влез в буфер %d: MTU устройства больше "+
					"согласованного", len(pkt), len(p))
			}
			return n, nil
		case windows.ERROR_NO_MORE_ITEMS:
			return 0, ErrAgain
		case windows.ERROR_HANDLE_EOF:
			return 0, fmt.Errorf("устройство закрыто")
		case windows.ERROR_INVALID_DATA:
			// Кольцо испорчено — это отказ уровня драйвера, дальше читать бессмысленно.
			return 0, fmt.Errorf("Wintun сообщил о порче кольца")
		default:
			return 0, err
		}
	}
}

// WaitRead ждёт события «в кольце что-то есть».
func (d *winDev) WaitRead(timeout time.Duration) (bool, error) {
	ms := uint32(timeout / time.Millisecond)
	r, err := windows.WaitForSingleObject(d.session.ReadWaitEvent(), ms)
	switch r {
	case windows.WAIT_OBJECT_0:
		return true, nil
	case uint32(windows.WAIT_TIMEOUT):
		return false, nil
	default:
		if err == nil {
			err = fmt.Errorf("ожидание события Wintun вернуло %#x", r)
		}
		return false, err
	}
}

// Write отдаёт пакет в кольцо. Переполнение — это перегрузка, а не отказ: пакет теряется, и
// внутренний TCP разберётся сам, как разбирается поверх любого канала.
func (d *winDev) Write(p []byte) (int, error) {
	pkt, err := d.session.AllocateSendPacket(len(p))
	switch err {
	case nil:
		copy(pkt, p)
		d.session.SendPacket(pkt)
		return len(p), nil
	case windows.ERROR_BUFFER_OVERFLOW:
		return 0, ErrAgain
	default:
		return 0, err
	}
}

func (d *winDev) Name() string { return d.name }

// SetMTU ставит MTU и заодно снимает автоматическую метрику интерфейса.
//
// Метрика здесь не косметика: с автоматической Windows назначает туннелю метрику по скорости
// адаптера, и маршрут по умолчанию через туннель может проиграть маршруту через физическую карту —
// снаружи это выглядит как «туннель поднят, а трафик идёт мимо». WireGuard делает то же самое.
func (d *winDev) SetMTU(mtu int) error {
	for _, family := range []winipcfg.AddressFamily{windows.AF_INET, windows.AF_INET6} {
		row, err := d.luid.IPInterface(family)
		if err != nil {
			if family == windows.AF_INET6 {
				continue // v6 может быть выключен на машине — это не наша беда
			}
			return err
		}
		row.NLMTU = uint32(mtu)
		row.UseAutomaticMetric = false
		row.Metric = 0
		if err := row.Set(); err != nil && family == windows.AF_INET {
			return err
		}
	}
	return nil
}

func (d *winDev) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	d.session.End()
	luidsMu.Lock()
	delete(luids, d.name)
	luidsMu.Unlock()
	return d.adapter.Close()
}

// SetAddr задаёт адрес внутри туннеля.
func SetAddr(name, cidr string) error {
	luid, err := luidOf(name)
	if err != nil {
		return err
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return fmt.Errorf("адрес %q не разобран: %w", cidr, err)
	}
	return luid.SetIPAddresses([]netip.Prefix{p})
}

// AddRoute направляет префикс в устройство.
//
// Шлюз — неопределённый адрес: маршрут «на канале», как и положено для точка-точка. Метрика нулевая,
// потому что автоматическую метрику интерфейса мы уже сняли в SetMTU.
func AddRoute(name, cidr string) error {
	luid, err := luidOf(name)
	if err != nil {
		return err
	}
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return fmt.Errorf("маршрут %q не разобран: %w", cidr, err)
	}
	err = luid.AddRoute(p, netip.IPv4Unspecified(), 0)
	if err == windows.ERROR_OBJECT_ALREADY_EXISTS {
		return nil
	}
	return err
}

// DevMTU — MTU, который сейчас стоит на устройстве.
func DevMTU(name string) int {
	luid, err := luidOf(name)
	if err != nil {
		return 0
	}
	row, err := luid.IPInterface(windows.AF_INET)
	if err != nil {
		return 0
	}
	return int(row.NLMTU)
}

func luidOf(name string) (winipcfg.LUID, error) {
	luidsMu.Lock()
	defer luidsMu.Unlock()
	l, ok := luids[name]
	if !ok {
		return 0, fmt.Errorf("адаптер %q не открыт этим процессом", name)
	}
	return l, nil
}
