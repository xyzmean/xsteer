//go:build !linux

package link

import (
	"fmt"
	"net"
	"runtime"
)

// EgressAddr на прочих системах — через обычный набор сокета. Тот же приём и та же цена: connect на
// UDP не отправляет ни одного пакета, а адрес источника выбирает ядро.
func EgressAddr(daddr [4]byte) ([4]byte, error) {
	var out [4]byte
	c, err := net.Dial("udp4", fmt.Sprintf("%d.%d.%d.%d:443", daddr[0], daddr[1], daddr[2], daddr[3]))
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrPathGone, err)
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok || ua.IP.To4() == nil {
		return out, fmt.Errorf("%w: %s не назвал адрес источника", ErrPathGone, runtime.GOOS)
	}
	copy(out[:], ua.IP.To4())
	return out, nil
}
