//go:build windows

package tun

import (
	"crypto/sha256"
	"errors"
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

// SetTxQueueLen на Windows делать нечего, и это не заглушка «до лучших времён».
//
// txqueuelen — длина очереди пакетов, которую ядро Linux держит для читателя устройства. У Wintun
// её роль исполняет кольцевой буфер в разделяемой памяти, и его размер задан при открытии адаптера
// (четыре мегабайта, как у WireGuard) — то есть запас здесь уже взят, только другой единицей и в
// другом месте. Возвращать отсюда ошибку значило бы учить вызывающего печатать «очередь осталась
// ядерной» там, где никакой ядерной очереди не существует.
func SetTxQueueLen(name string, n int) error { _, _ = name, n; return nil }

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

// bypassRoute — маршрут /32 к адресу хаба, поставленный НЕ на туннель, а на физический
// интерфейс. Его надо запомнить, чтобы снять при выходе: он живёт на чужом интерфейсе и сам
// вместе с адаптером Wintun не исчезнет.
type bypassRoute struct {
	luid winipcfg.LUID
	pfx  netip.Prefix
	gw   netip.Addr
}

// devRoutes — всё, что мы навесили на систему ради одного устройства.
//
// Учёт ведётся ЯВНО, а не «уйдёт вместе с адаптером». Первая версия полагалась на закрытие
// адаптера, и живой стенд показал цену: после аварийного завершения в таблице маршрутов
// оставался обход /32 к хабу. Маршрут на ЧУЖОМ интерфейсе переживает наш процесс, и снимать
// его обязан тот, кто поставил.
type devRoutes struct {
	luid      winipcfg.LUID
	bypass    []bypassRoute
	tunnel    []netip.Prefix
	defaultUp bool
	dnsSet    bool
}

var (
	routesMu sync.Mutex
	routesOf = map[string]*devRoutes{}
)

func routesFor(name string) (*devRoutes, error) {
	luid, err := luidOf(name)
	if err != nil {
		return nil, err
	}
	routesMu.Lock()
	defer routesMu.Unlock()
	r, ok := routesOf[name]
	if !ok {
		r = &devRoutes{luid: luid}
		routesOf[name] = r
	}
	return r, nil
}

// halves — две половины маршрута по умолчанию.
//
// Простой 0.0.0.0/0 на туннеле спорит с физическим 0.0.0.0/0 по метрикам интерфейсов, и кто
// победит — как повезёт. У двух половин маска на бит длиннее, а по правилу «самый длинный
// префикс побеждает» они бьют любой /0 независимо от метрик. Тот же приём у WireGuard для
// Windows. Снимаются они поимённо и не трогают чужой маршрут по умолчанию — а именно это и
// нужно, чтобы вернуть человеку сеть.
var halves = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/1"),
	netip.MustParsePrefix("128.0.0.0/1"),
}

// DefaultRouteUp уводит маршрут по умолчанию в туннель. Зовётся ТОЛЬКО после того, как туннель
// подтвердил, что несёт трафик, — см. пояснение у SetupRoutes.
func DefaultRouteUp(name string) error {
	r, err := routesFor(name)
	if err != nil {
		return err
	}
	routesMu.Lock()
	defer routesMu.Unlock()
	if r.defaultUp {
		return nil
	}
	for _, hp := range halves {
		if e := r.luid.AddRoute(hp, netip.IPv4Unspecified(), 0); e != nil && e != windows.ERROR_OBJECT_ALREADY_EXISTS {
			// Половина не встала — снимаем ту, что успела. Одна половина без второй означает
			// «половина интернета в туннеле, половина мимо», и это хуже любого из двух исходов.
			for _, done := range halves {
				_ = r.luid.DeleteRoute(done, netip.IPv4Unspecified())
			}
			return fmt.Errorf("половина маршрута по умолчанию %s не встала: %w", hp, e)
		}
	}
	r.defaultUp = true
	return nil
}

// DefaultRouteDown возвращает маршрут по умолчанию физическому интерфейсу.
//
// Снимаются ровно наши две половины: физический /0 мы никогда не удаляли, поэтому он снова
// становится лучшим маршрутом сам, без восстановления чего бы то ни было.
func DefaultRouteDown(name string) {
	routesMu.Lock()
	r, ok := routesOf[name]
	if !ok || !r.defaultUp {
		routesMu.Unlock()
		return
	}
	r.defaultUp = false
	luid := r.luid
	routesMu.Unlock()
	for _, hp := range halves {
		_ = luid.DeleteRoute(hp, netip.IPv4Unspecified())
	}
}

// DefaultRouteIsUp — держит ли туннель маршрут по умолчанию прямо сейчас.
func DefaultRouteIsUp(name string) bool {
	routesMu.Lock()
	defer routesMu.Unlock()
	r, ok := routesOf[name]
	return ok && r.defaultUp
}

// SetDNS задаёт серверы имён на устройстве туннеля.
//
// Без этого полный туннель течёт именем: запросы уходят серверу физического интерфейса — обычно
// это адрес роутера, — и провайдер видит, куда человек ходит, хотя сам трафик спрятан. WireGuard
// для Windows делает ровно это же и по той же причине.
func SetDNS(name string, servers []string) error {
	r, err := routesFor(name)
	if err != nil {
		return err
	}
	var addrs []netip.Addr
	for _, s := range servers {
		a, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return fmt.Errorf("адрес DNS %q не разобран: %w", s, err)
		}
		if !a.Is4() {
			continue // v6 внутри туннеля пока не несём
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 {
		return nil
	}
	if err := r.luid.SetDNS(windows.AF_INET, addrs, nil); err != nil {
		return err
	}
	routesMu.Lock()
	r.dnsSet = true
	routesMu.Unlock()
	return nil
}

// SetupRoutes ставит на устройство маршруты AllowedIPs — КРОМЕ маршрута по умолчанию.
//
// Полный туннель (0.0.0.0/0) здесь только ОБЪЯВЛЯЕТСЯ: функция возвращает full=true и ставит
// обход /32 к хабу, но самого маршрута по умолчанию не трогает. Уводить его должен
// DefaultRouteUp — и только после того, как туннель ДОКАЗАЛ, что несёт трафик.
//
// Почему так, а не сразу. Маршрут по умолчанию, уведённый в канал, который ничего не несёт, —
// это не «туннель не работает», это «интернета нет вовсе», и снаружи оно неотличимо от
// сломанной сети. Ровно это ловилось на живом стенде: рукопожатие проходит, хаб подтверждает
// каждый наш сегмент и не отвечает ни байтом, а машина остаётся без сети до Ctrl-C. Порядок
// «сначала докажи, потом забирай» превращает отказ хаба в «туннель не поднялся» вместо
// «выключился интернет».
//
// Обход же ставится СРАЗУ и первым. Он никому не мешает — это тот же путь, которым пакеты к
// хабу и так идут, — а понадобиться может в ту же секунду, когда маршрут по умолчанию уедет:
// собственные пакеты клиента к хабу тоже подпадают под 0.0.0.0/0 и без обхода ушли бы в
// туннель, который ими же и держится.
func SetupRoutes(name string, cidrs, endpoints []string) (bool, error) {
	r, err := routesFor(name)
	if err != nil {
		return false, err
	}
	full := false
	for _, c := range cidrs {
		if p, e := netip.ParsePrefix(strings.TrimSpace(c)); e == nil && p.Bits() == 0 && p.Addr().Is4() {
			full = true
			break
		}
	}
	// Обход для адреса хаба нужен НЕ только при 0.0.0.0/0. Полный туннель с исключениями
	// («весь трафик, кроме локальных сетей») не содержит /0, но его префиксы всё равно
	// накрывают адрес хаба — например, 104.0.0.0/5 включает 109.120.137.190. Без обхода
	// собственное соединение клиента к хабу уходит в ещё не поднятый туннель, и это видно как
	// «dial tcp …: i/o timeout». Поэтому обход ставится всегда, когда какой-либо маршрут
	// накрывает конечную точку, а не только при литеральном /0.
	if full || endpointCovered(cidrs, endpoints) {
		if err := addEndpointBypass(r, endpoints); err != nil {
			return full, err
		}
	}
	// Список префиксов раскладывается ЦЕЛИКОМ, и отказ на одном не прекращает работу над
	// остальными. Раньше здесь стоял return на первой же ошибке, и это давало худший вид сбоя:
	// у полного туннеля с исключениями префиксов девятнадцать, и упади одиннадцатый — маршруты
	// с двенадцатого по девятнадцатый не ставились вовсе. Снаружи это выглядит как «туннель
	// работает, но часть адресов ходит мимо него», причём молча: интернет-то есть.
	var failed []string
	okN := 0
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s (не разобран: %v)", c, err))
			continue
		}
		if p.Bits() == 0 && p.Addr().Is4() {
			continue // маршрут по умолчанию — забота DefaultRouteUp
		}
		if e := r.luid.AddRoute(p, netip.IPv4Unspecified(), 0); e != nil && e != windows.ERROR_OBJECT_ALREADY_EXISTS {
			failed = append(failed, fmt.Sprintf("%s (%v)", c, e))
			continue
		}
		okN++
		routesMu.Lock()
		r.tunnel = append(r.tunnel, p)
		routesMu.Unlock()
	}
	if len(failed) > 0 {
		return full, fmt.Errorf("в туннель направлено префиксов %d из %d; не встали: %s",
			okN, len(cidrs), strings.Join(failed, "; "))
	}
	return full, nil
}

// addEndpointBypass ставит /32 к каждому адресу хаба через ПРЕЖНИЙ маршрут по умолчанию —
// тот, что был до туннеля, — чтобы пакеты самого туннеля продолжали ходить физическим каналом.
func addEndpointBypass(r *devRoutes, endpoints []string) error {
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return fmt.Errorf("таблица маршрутов не прочиталась: %w", err)
	}
	// Лучший физический маршрут по умолчанию: нулевой префикс, не наш туннель, наименьшая
	// метрика. Его шлюз и интерфейс и станут обходом для хаба.
	var best *winipcfg.MibIPforwardRow2
	for i := range rows {
		row := &rows[i]
		if row.InterfaceLUID == r.luid {
			continue
		}
		dp := row.DestinationPrefix.Prefix()
		if dp.Bits() != 0 || !dp.Addr().Is4() {
			continue
		}
		if best == nil || row.Metric < best.Metric {
			best = row
		}
	}
	if best == nil {
		return errors.New("не нашёл физический маршрут по умолчанию — обход для хаба поставить не на что")
	}
	gw := best.NextHop.Addr()
	physLUID := best.InterfaceLUID

	for _, ep := range endpoints {
		addr, err := netip.ParseAddr(strings.TrimSpace(ep))
		if err != nil || !addr.Is4() {
			continue
		}
		pfx := netip.PrefixFrom(addr, 32)
		if e := physLUID.AddRoute(pfx, gw, 0); e != nil && e != windows.ERROR_OBJECT_ALREADY_EXISTS {
			return fmt.Errorf("обход к хабу %s не встал: %w", ep, e)
		}
		routesMu.Lock()
		r.bypass = append(r.bypass, bypassRoute{luid: physLUID, pfx: pfx, gw: gw})
		routesMu.Unlock()
	}
	return nil
}

// TeardownRoutes снимает ВСЁ, что поставило устройство: маршрут по умолчанию, префиксы туннеля,
// серверы имён и обход к хабу.
//
// Обход снимается поимённо: он лежит на ФИЗИЧЕСКОМ интерфейсе, и закрытие адаптера Wintun его
// не заденет. Именно он и оставался висеть в таблице после аварийного завершения — маршрут
// 109.120.137.190/32 через прежний шлюз пережил и процесс, и перезагрузку окна консоли.
func TeardownRoutes(name string) {
	DefaultRouteDown(name)
	routesMu.Lock()
	r, ok := routesOf[name]
	if ok {
		delete(routesOf, name)
	}
	routesMu.Unlock()
	if !ok {
		return
	}
	if r.dnsSet {
		_ = r.luid.FlushDNS(windows.AF_INET)
	}
	for _, p := range r.tunnel {
		_ = r.luid.DeleteRoute(p, netip.IPv4Unspecified())
	}
	for _, b := range r.bypass {
		_ = b.luid.DeleteRoute(b.pfx, b.gw)
	}
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
