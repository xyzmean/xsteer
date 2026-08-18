//go:build !linux

package tun

import (
	"fmt"
	"runtime"
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

func SetAddr(name, cidr string) error { return fmt.Errorf("не сделано на %s", runtime.GOOS) }
func AddRoute(name, cidr string) error {
	return fmt.Errorf("не сделано на %s", runtime.GOOS)
}
func DevMTU(name string) int { return 0 }
