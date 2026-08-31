package link

import (
	"math/rand/v2"
	"testing"
)

// csumSlow — прежняя реализация: сумма 16-битных слов в сетевом порядке, слово за словом. Оставлена
// ЗДЕСЬ, а не в рабочем коде, ровно для одной задачи: доказать, что быстрый проход по восемь байт
// даёт то же число. Тождество, на котором он стоит (перестановка байт свёрнутой суммы), проверяется
// не рассуждением, а на всех длинах и на случайных данных.
func csumSlow(saddr, daddr [4]byte, seg []byte) uint16 {
	var s uint32
	s += uint32(saddr[0])<<8 | uint32(saddr[1])
	s += uint32(saddr[2])<<8 | uint32(saddr[3])
	s += uint32(daddr[0])<<8 | uint32(daddr[1])
	s += uint32(daddr[2])<<8 | uint32(daddr[3])
	s += 6
	s += uint32(len(seg))
	for i := 0; i+1 < len(seg); i += 2 {
		s += uint32(seg[i])<<8 | uint32(seg[i+1])
	}
	if len(seg)&1 != 0 {
		s += uint32(seg[len(seg)-1]) << 8
	}
	for s>>16 != 0 {
		s = s&0xFFFF + s>>16
	}
	return uint16(^s)
}

func TestCsumSameAsSlow(t *testing.T) {
	sa := [4]byte{192, 0, 2, 1}
	da := [4]byte{198, 51, 100, 7}
	// Все длины до 96 подряд: там живут все нечётные хвосты и все неполные шаги разворота.
	for n := 0; n <= 96; n++ {
		seg := make([]byte, n)
		for i := range seg {
			seg[i] = byte(i*31 + 7)
		}
		if got, want := Csum(sa, da, seg), csumSlow(sa, da, seg); got != want {
			t.Fatalf("длина %d: %04x против %04x", n, got, want)
		}
	}
	// Случайные данные на длинах пакета: 1460 и предельная запись.
	r := rand.New(rand.NewPCG(1, 2))
	for _, n := range []int{20, 60, 1460, 1480, 8213, 8214} {
		for k := 0; k < 200; k++ {
			seg := make([]byte, n)
			for i := range seg {
				seg[i] = byte(r.UintN(256))
			}
			var a1, a2 [4]byte
			for i := range a1 {
				a1[i] = byte(r.UintN(256))
				a2[i] = byte(r.UintN(256))
			}
			if got, want := Csum(a1, a2, seg), csumSlow(a1, a2, seg); got != want {
				t.Fatalf("длина %d, прогон %d: %04x против %04x", n, k, got, want)
			}
		}
	}
}

// TestCsumZeroOnBuilt — свойство, которым сумму проверяет любой стек: посчитанная над готовым
// сегментом (с уже записанной суммой) она даёт ноль.
func TestCsumZeroOnBuilt(t *testing.T) {
	sa := [4]byte{10, 0, 0, 1}
	da := [4]byte{10, 0, 0, 2}
	for _, plen := range []int{0, 1, 2, 3, 40, 1440, 1441} {
		payload := make([]byte, plen)
		for i := range payload {
			payload[i] = byte(i)
		}
		buf := make([]byte, 60+plen)
		n := BuildSeg(buf, sa, da, 443, 55555, 1, 2, PSH|ACK, OptNone, payload)
		if got := Csum(sa, da, buf[:n]); got != 0 {
			t.Fatalf("нагрузка %d: сумма готового сегмента %04x, а не ноль", plen, got)
		}
	}
}
