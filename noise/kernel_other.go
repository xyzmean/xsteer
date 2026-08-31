//go:build !linux

package noise

import (
	"fmt"
	"runtime"
)

// AF_ALG — механизм Linux, и на прочих системах его нет. Ядерная криптография там недоступна не
// «пока», а принципиально: у Windows своя CNG, у macOS своя CommonCrypto, и обе доступны не
// сокетом, а библиотекой — то есть это отдельная работа с отдельной обвязкой, а не тот же код.
//
// Отказ назван прямо, потому что заглушка, молча возвращающая Go, означала бы «ядро выбрано» без
// ядра.
func newKernelSealer(kind AEAD, key []byte) (sealer, error) {
	return nil, fmt.Errorf("ядерная криптография на %s недоступна: AF_ALG есть только у Linux",
		runtime.GOOS)
}

// KernelUsable — на прочих системах всегда «нет», и причина названа.
func KernelUsable(kind AEAD, probe bool) (bool, string) {
	return false, "AF_ALG есть только у Linux, а здесь " + runtime.GOOS
}

// KernelDriver — сказать нечего.
func KernelDriver(kind AEAD) string { return "" }
