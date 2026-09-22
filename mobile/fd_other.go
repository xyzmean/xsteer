//go:build !linux

package xsteer

import (
	"fmt"
	"runtime"

	"github.com/xyzmean/xsteer/tun"
)

// На iOS туннель не даёт дескриптора: пакеты ходят вызовами через NEPacketTunnelFlow. Отказ
// здесь — не заглушка до лучших времён, а прямое «этого способа тут не существует»: молча
// вернуть устройство-пустышку значило бы показать работающий туннель, которого нет.
func newFDDevice(fd int, name string, mtu int) (tun.Device, error) {
	_, _, _ = fd, name, mtu
	return nil, fmt.Errorf("на %s туннель не даёт дескриптора: поднимайте через Start", runtime.GOOS)
}

var _ = tun.ErrNoDevice
