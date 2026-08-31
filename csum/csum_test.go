package csum

import (
	"math/rand/v2"
	"strconv"
	"testing"
)

// refTCPv4 — определение суммы из RFC, слово за словом в сетевом порядке. Оно и есть эталон:
// быстрый проход стоит на тождестве о перестановке байт, и проверять это тождество надо не
// рассуждением, а на всех длинах.
func refTCPv4(saddr, daddr [4]byte, seg []byte) uint16 {
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

func TestTCPv4MatchesReference(t *testing.T) {
	sa := [4]byte{192, 0, 2, 1}
	da := [4]byte{198, 51, 100, 7}
	for n := 0; n <= 130; n++ {
		seg := make([]byte, n)
		for i := range seg {
			seg[i] = byte(i*31 + 7)
		}
		if got, want := TCPv4(sa, da, seg), refTCPv4(sa, da, seg); got != want {
			t.Fatalf("длина %d: %04x против %04x", n, got, want)
		}
	}
	r := rand.New(rand.NewPCG(7, 11))
	for _, n := range []int{20, 1460, 8213, 65515} {
		for k := 0; k < 100; k++ {
			seg := make([]byte, n)
			for i := range seg {
				seg[i] = byte(r.UintN(256))
			}
			var a, b [4]byte
			for i := range a {
				a[i] = byte(r.UintN(256))
				b[i] = byte(r.UintN(256))
			}
			if got, want := TCPv4(a, b, seg), refTCPv4(a, b, seg); got != want {
				t.Fatalf("длина %d прогон %d: %04x против %04x", n, k, got, want)
			}
		}
	}
}

// TestFoldNoInvIsFoldComplement — поле, оставленное под разгрузку устройству, отличается от готовой
// суммы ровно дополнением. Свойство закреплено тестом, потому что перепутать эти две функции —
// значит отдать ядру сумму, которую оно достроит в мусор, и увидеть это только на живом трафике.
func TestFoldNoInvIsFoldComplement(t *testing.T) {
	for i := 0; i < 1000; i++ {
		s := uint64(i) * 7919
		a, b := Fold(s), FoldNoInv(s)
		if a != ^b {
			t.Fatalf("сумма %d: %04x против ^%04x", s, a, b)
		}
	}
}

func BenchmarkTCPv4(b *testing.B) {
	for _, n := range []int{60, 148, 596, 1460, 8192} {
		seg := make([]byte, n)
		for i := range seg {
			seg[i] = byte(i * 7)
		}
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			for i := 0; i < b.N; i++ {
				TCPv4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, seg)
			}
		})
	}
}

// BenchmarkRefTCPv4 — тот же замер над эталоном. Стоит рядом нарочно: «стало быстрее» без второго
// числа в том же прогоне на том же железе — не утверждение.
func BenchmarkRefTCPv4(b *testing.B) {
	for _, n := range []int{60, 1460} {
		seg := make([]byte, n)
		for i := range seg {
			seg[i] = byte(i * 7)
		}
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			b.SetBytes(int64(n))
			for i := 0; i < b.N; i++ {
				refTCPv4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, seg)
			}
		})
	}
}
