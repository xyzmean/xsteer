//go:build windows

package tun

import (
	"errors"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Привязка СВОЕГО сокета к физическому интерфейсу — вместо исключения адреса хаба из туннеля.
//
// ЗАЧЕМ. Полный туннель накрывает и адрес самого хаба, поэтому соединение клиента к хабу без мер
// уходит в туннель, которого ещё нет («dial tcp …: i/o timeout»). Первое решение было маршрутом
// /32 к хабу через физический шлюз — и оно неверно по существу: такой маршрут выносит из туннеля
// ВЕСЬ трафик к адресу хаба, включая чужой. Ssh на тот же сервер шёл мимо туннеля, а там его мог
// не пустить брандмауэр сети (порт хаба 3389 выбран как раз потому, что 22 наружу закрыт) — и
// снаружи это выглядело как «через VPN не пробросить ssh к хосту».
//
// ПРАВИЛЬНО — исключить не адрес, а СОКЕТ: IP_UNICAST_IF заставляет наши собственные пакеты уйти
// через названный интерфейс, минуя таблицу маршрутов. Тогда чужой трафик к тому же адресу
// (ssh, http, что угодно) спокойно идёт туннелем, а туннель не съедает своё же соединение. Так же
// поступает WireGuard для Windows со своим сокетом.
//
// ТОНКОСТЬ БАЙТОВОГО ПОРЯДКА. Для IPv4 индекс интерфейса передаётся в СЕТЕВОМ порядке, для IPv6 —
// в хостовом. Ошибка здесь не заметна на глаз: опция примется, а пакеты пойдут не туда.
const ipUnicastIF = 31 // IP_UNICAST_IF, уровень IPPROTO_IP

// PhysicalIndex — индекс интерфейса, через который система выходит наружу, не считая устройства
// dev (нашего туннеля). Читается ДО того, как в таблицу встанут маршруты туннеля.
func PhysicalIndex(dev string) (uint32, error) {
	var skip winipcfg.LUID
	if l, err := luidOf(dev); err == nil {
		skip = l
	}
	rows, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return 0, fmt.Errorf("таблица маршрутов не прочиталась: %w", err)
	}
	var best *winipcfg.MibIPforwardRow2
	for i := range rows {
		row := &rows[i]
		if skip != 0 && row.InterfaceLUID == skip {
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
		return 0, errors.New("не нашёл физический маршрут по умолчанию")
	}
	return best.InterfaceIndex, nil
}

// DialControl отдаёт хук для net.Dialer.Control, привязывающий сокет к физическому интерфейсу.
// Второе значение — индекс этого интерфейса, для журнала. Ошибка означает «привязать не удалось»:
// вызывающий тогда возвращается к маршруту-обходу, который хуже, но лучше неработающего туннеля.
func DialControl(dev string) (func(network, address string, c syscall.RawConn) error, uint32, error) {
	idx, err := PhysicalIndex(dev)
	if err != nil {
		return nil, 0, err
	}
	// Сетевой порядок для IPv4: младший байт индекса уезжает старшим.
	be := (idx&0xff)<<24 | (idx&0xff00)<<8 | (idx&0xff0000)>>8 | (idx&0xff000000)>>24
	return func(network, address string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, ipUnicastIF, int(be))
		}); err != nil {
			return err
		}
		return serr
	}, idx, nil
}
