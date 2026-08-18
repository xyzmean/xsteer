//go:build !linux

package tun

import (
	"fmt"
	"runtime"
	"time"
)

// Open на прочих системах пока не реализован. Отказ называет, что именно требуется, — заглушка,
// молча возвращающая устройство-пустышку, выглядела бы как работающий туннель.
//
// macOS: utun через AF_SYSTEM (перед каждым пакетом четыре байта семейства адресов), плюс
// настройка адреса через ifconfig.
// Windows: Wintun — своя библиотека с кольцевым буфером вместо чтения дескриптора; ставится
// вместе с драйвером.
func Open(name string) (Device, error) {
	return nil, fmt.Errorf("%w: TUN на %s ещё не сделан", ErrNoDevice, runtime.GOOS)
}

// OpenQueues — то же самое: пока нечего открывать.
func OpenQueues(name string, n int) ([]Device, error) {
	_, err := Open(name)
	return nil, err
}

// notImplemented — заглушка устройства: нужна только чтобы интерфейс был реализован целиком и
// компилятор ловил расхождения, а не чтобы ею пользовались.
type notImplemented struct{}

func (notImplemented) Read([]byte) (int, error)             { return 0, ErrNoDevice }
func (notImplemented) Write([]byte) (int, error)            { return 0, ErrNoDevice }
func (notImplemented) WaitRead(time.Duration) (bool, error) { return false, ErrNoDevice }
func (notImplemented) Name() string                         { return "" }
func (notImplemented) SetMTU(int) error                     { return ErrNoDevice }
func (notImplemented) Close() error                         { return nil }

func SetAddr(name, cidr string) error { return fmt.Errorf("не сделано на %s", runtime.GOOS) }
func AddRoute(name, cidr string) error {
	return fmt.Errorf("не сделано на %s", runtime.GOOS)
}
func DevMTU(name string) int { return 0 }
