//go:build !windows

package tun

import (
	"errors"
	"syscall"
)

// DialControl на прочих системах не нужен: там маршрутами туннеля распоряжается движок (на роутере
// — своими таблицами и правилами fwmark), и своё соединение он из туннеля исключает сам. Ошибка
// здесь — не отказ, а «привязывать нечего»: вызывающий просто не ставит хук.
func DialControl(dev string) (func(network, address string, c syscall.RawConn) error, uint32, error) {
	_ = dev
	return nil, 0, errors.New("привязка сокета к интерфейсу нужна только на Windows")
}
