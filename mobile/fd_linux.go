//go:build linux

package xsteer

import "github.com/xyzmean/xsteer/tun"

// Дескриптор туннеля бывает только там, где есть /dev/net/tun, то есть на Linux и на Android
// (сборка под android включает тег linux). На iOS дескриптора нет вовсе — там пакеты ходят
// вызовами, см. Device в device.go.
func newFDDevice(fd int, name string, mtu int) (tun.Device, error) {
	return tun.FromFD(fd, name, mtu)
}
