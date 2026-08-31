//go:build linux

package link

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// EgressAddr — с какого адреса ядро СЕЙЧАС уходит к daddr, и есть ли к нему путь вообще.
//
// ЗАЧЕМ. Это единственный честный способ ответить на вопрос «сеть та же, что была?». Читать таблицу
// маршрутизации самим значило бы повторять её разбор — правила, метки, несколько таблиц, — и всё
// равно разойтись с ядром в частном случае. Здесь решение принимает само ядро, тем же кодом, которым
// оно выберет путь настоящему сокету.
//
// Пакетов не уходит ни одного: connect на UDP только выбирает путь и закрепляет адрес источника.
// Отказ ENETUNREACH — это ответ, а не сбой: пути наружу нет, и вызывающему надо знать именно это.
func EgressAddr(daddr [4]byte) ([4]byte, error) {
	var out [4]byte
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.IPPROTO_UDP)
	if err != nil {
		return out, err
	}
	defer unix.Close(fd)
	// Порт произвольный: путь выбирается по адресу, а порт нужен лишь для того, чтобы connect
	// состоялся.
	if err := unix.Connect(fd, &unix.SockaddrInet4{Addr: daddr, Port: 443}); err != nil {
		return out, fmt.Errorf("%w: %v", ErrPathGone, err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		return out, err
	}
	in4, ok := sa.(*unix.SockaddrInet4)
	if !ok {
		return out, fmt.Errorf("%w: ядро не назвало адрес источника", ErrPathGone)
	}
	return in4.Addr, nil
}
