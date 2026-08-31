//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/xyzmean/xsteer/csum"
)

// mkTCP4 собирает настоящий пакет IPv4 с сегментом TCP: обе суммы верные, длины сходятся.
//
// Опции TCP задаются длиной opt (кратной четырём) и заполняются меткой времени — не для красоты, а
// потому что заголовок с опциями это отдельный случай в склейке: у каждого сегмента метка своя, и
// склейка обязана взять последнюю.
func mkTCP4(t *testing.T, id uint16, sport, dport uint16, seq, ack uint32, flags byte,
	optLen int, payload []byte) []byte {
	t.Helper()
	if optLen%4 != 0 {
		t.Fatalf("опции TCP кратны четырём, а не %d", optLen)
	}
	thl := 20 + optLen
	p := make([]byte, 20+thl+len(payload))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], id)
	p[6] = 0x40 // DF
	p[8] = 64
	p[9] = 6
	copy(p[12:16], []byte{10, 0, 0, 1})
	copy(p[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(p[10:12], csum.Of(p[:20]))

	th := p[20:]
	binary.BigEndian.PutUint16(th[0:2], sport)
	binary.BigEndian.PutUint16(th[2:4], dport)
	binary.BigEndian.PutUint32(th[4:8], seq)
	binary.BigEndian.PutUint32(th[8:12], ack)
	th[12] = byte(thl/4) << 4
	th[13] = flags
	binary.BigEndian.PutUint16(th[14:16], 64000)
	for i := 0; i < optLen; i++ {
		th[20+i] = byte(0xA0 + i)
	}
	copy(th[thl:], payload)
	binary.BigEndian.PutUint16(th[16:18], csum.Fold(
		csum.PseudoV4(p[12:16], p[16:20], 6, len(th))+csum.Sum(th)))
	return p
}

// run — набор подряд идущих сегментов одного потока: четыре полноразмерных и короткий хвост, PSH на
// последнем, идентификатор IP растёт на сегмент. Ровно то, что ядро склеило бы в один супер-кадр.
func segRun(t *testing.T, optLen int) [][]byte {
	t.Helper()
	const gso = 1400
	var out [][]byte
	seq := uint32(0x1000)
	sizes := []int{gso, gso, gso, gso, 617}
	for i, n := range sizes {
		body := make([]byte, n)
		for j := range body {
			body[j] = byte(i*7 + j)
		}
		flags := byte(0x10) // ACK
		if i == len(sizes)-1 {
			flags = 0x18 // PSH|ACK — только на последнем
		}
		out = append(out, mkTCP4(t, uint16(100+i), 12345, 443, seq, 0x9000, flags, optLen, body))
		seq += uint32(n)
	}
	return out
}

// frameOf собирает супер-кадр так, как его отдаёт ядро: заголовок первого сегмента, вся нагрузка
// подряд, длина IP по всему кадру, в поле суммы TCP — свёрнутая сумма псевдозаголовка, метаданные с
// размером сегмента.
func frameOf(t *testing.T, segs [][]byte, gso int) []byte {
	t.Helper()
	first := segs[0]
	thl := int(first[20+12]>>4) * 4
	hdrLen := 20 + thl
	f := make([]byte, vnetHdrLen+hdrLen)
	copy(f[vnetHdrLen:], first[:hdrLen])
	for _, s := range segs {
		f = append(f, s[hdrLen:]...)
	}
	pkt := f[vnetHdrLen:]
	// В склеенном кадре ядро держит номер и идентификатор ПЕРВОГО сегмента, а подтверждение, окно и
	// опции — ПОСЛЕДНЕГО; флаг PSH накапливается. Номер последовательности первого при этом не
	// трогается: из него считаются номера всех сегментов при разборе.
	last := segs[len(segs)-1]
	copy(pkt[20+8:20+12], last[20+8:20+12])   // подтверждение
	copy(pkt[20+14:20+16], last[20+14:20+16]) // окно
	if hdrLen > 40 {
		copy(pkt[40:hdrLen], last[40:hdrLen]) // опции последнего
	}
	pkt[20+13] |= last[20+13] & 0x08
	binary.BigEndian.PutUint16(pkt[2:4], uint16(len(pkt)))
	binary.BigEndian.PutUint16(pkt[4:6], binary.BigEndian.Uint16(first[4:6]))
	pkt[10], pkt[11] = 0, 0
	binary.BigEndian.PutUint16(pkt[10:12], csum.Of(pkt[:20]))
	th := pkt[20:]
	binary.BigEndian.PutUint16(th[16:18], csum.FoldNoInv(
		csum.PseudoV4(pkt[12:16], pkt[16:20], 6, len(th))))
	f[0] = vnetNeedsCsum
	f[1] = vnetGSOTCPv4
	// Порядок ХОСТА, как его читает ядро: см. оговорку в offload_linux.go.
	vnetPut(f[2:4], uint16(hdrLen))
	vnetPut(f[4:6], uint16(gso))
	vnetPut(f[6:8], 20)
	vnetPut(f[8:10], 16)
	return f
}

// readAll вычитывает из разгрузки ровно want пакетов.
func readAll(t *testing.T, o *offload, want int) [][]byte {
	t.Helper()
	var got [][]byte
	buf := make([]byte, 2048)
	for i := 0; i < want; i++ {
		n, err := o.read(buf)
		if err != nil {
			t.Fatalf("пакет %d: %v", i, err)
		}
		got = append(got, bytes.Clone(buf[:n]))
	}
	return got
}

// TestOffloadSplitEqualsOriginal — главное свойство приёма: пакеты, полученные разбором
// супер-кадра, обязаны быть ПОБАЙТОВО теми же, что пришли бы без склейки. Иначе стек пира увидит
// поток, которого не бывает, — и это самый неуловимый класс отказов: туннель поднят, трафик идёт,
// часть соединений встаёт.
func TestOffloadSplitEqualsOriginal(t *testing.T) {
	for _, optLen := range []int{0, 12} {
		segs := segRun(t, optLen)
		frame := frameOf(t, segs, 1400)
		fed := false
		o := newOffload(func(p []byte) (int, error) {
			if fed {
				return 0, ErrAgain
			}
			fed = true
			return copy(p, frame), nil
		}, nil)
		got := readAll(t, o, len(segs))
		for i := range segs {
			if !bytes.Equal(got[i], segs[i]) {
				t.Fatalf("опции %d, сегмент %d разошёлся\nбыло:  %x\nстало: %x",
					optLen, i, segs[i], got[i])
			}
		}
		if o.Dropped != 0 {
			t.Fatalf("опции %d: отброшено %d", optLen, o.Dropped)
		}
	}
}

// TestOffloadRoundTrip — склейка и разбор обратны друг другу. Проверяет обе половины разом и на том
// же наборе: пакеты уходят в отправку по одному, уезжают одним кадром, разбираются обратно и
// обязаны совпасть побайтово.
func TestOffloadRoundTrip(t *testing.T) {
	for _, optLen := range []int{0, 12} {
		segs := segRun(t, optLen)
		var frames [][]byte
		o := newOffload(nil, func(p []byte) (int, error) {
			frames = append(frames, bytes.Clone(p))
			return len(p), nil
		})
		for _, s := range segs {
			if _, err := o.write(s); err != nil {
				t.Fatal(err)
			}
		}
		if err := o.Flush(); err != nil {
			t.Fatal(err)
		}
		if len(frames) != 1 {
			t.Fatalf("опции %d: кадров %d, а пробег один", optLen, len(frames))
		}
		i := 0
		in := newOffload(func(p []byte) (int, error) {
			if i > 0 {
				return 0, ErrAgain
			}
			i++
			return copy(p, frames[0]), nil
		}, nil)
		got := readAll(t, in, len(segs))
		for k := range segs {
			if !bytes.Equal(got[k], segs[k]) {
				t.Fatalf("опции %d, сегмент %d после круга разошёлся\nбыло:  %x\nстало: %x",
					optLen, k, segs[k], got[k])
			}
		}
	}
}

// TestOffloadBreaksRun — пробег обязан закрываться там, где ядро тоже не склеивает. Каждый случай
// здесь однажды стоил бы порчи потока: дыра в номерах превратилась бы в чужие байты внутри записи,
// смешанные потоки — в пакет не тому получателю.
func TestOffloadBreaksRun(t *testing.T) {
	base := segRun(t, 0)
	cases := []struct {
		name string
		pkts func() [][]byte
		want int
	}{
		{"дыра в номерах", func() [][]byte {
			p := [][]byte{base[0], mkTCP4(t, 200, 12345, 443, 0x1000+1400+7, 0x9000, 0x10, 0,
				make([]byte, 1400))}
			return p
		}, 2},
		{"другой поток", func() [][]byte {
			return [][]byte{base[0], mkTCP4(t, 200, 12346, 443, 0x1000+1400, 0x9000, 0x10, 0,
				make([]byte, 1400))}
		}, 2},
		{"короткий в середине", func() [][]byte {
			short := mkTCP4(t, 101, 12345, 443, 0x1000+1400, 0x9000, 0x10, 0, make([]byte, 100))
			after := mkTCP4(t, 102, 12345, 443, 0x1000+1500, 0x9000, 0x10, 0, make([]byte, 1400))
			return [][]byte{base[0], short, after}
		}, 2},
		{"голое подтверждение", func() [][]byte {
			bare := mkTCP4(t, 101, 12345, 443, 0x1000+1400, 0x9000, 0x10, 0, nil)
			return [][]byte{base[0], bare, base[1]}
		}, 3},
		{"SYN", func() [][]byte {
			syn := mkTCP4(t, 101, 12345, 443, 0x1000+1400, 0x9000, 0x12, 0, make([]byte, 8))
			return [][]byte{base[0], syn}
		}, 2},
		{"не TCP", func() [][]byte {
			u := mkTCP4(t, 101, 12345, 443, 0, 0, 0x10, 0, make([]byte, 100))
			u[9] = 17 // UDP
			binary.BigEndian.PutUint16(u[10:12], 0)
			binary.BigEndian.PutUint16(u[10:12], csum.Of(u[:20]))
			return [][]byte{base[0], u}
		}, 2},
	}
	for _, c := range cases {
		var frames int
		o := newOffload(nil, func(p []byte) (int, error) { frames++; return len(p), nil })
		for _, p := range c.pkts() {
			if _, err := o.write(p); err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
		}
		if err := o.Flush(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if frames != c.want {
			t.Fatalf("%s: кадров %d, ожидалось %d", c.name, frames, c.want)
		}
	}
}

// TestOffloadFinClosesRun — после FIN пробег закрыт: сегмент за ним обязан уехать своим кадром.
// Иначе FIN достался бы не последнему сегменту склейки, то есть соединение закрылось бы раньше
// времени.
func TestOffloadFinClosesRun(t *testing.T) {
	a := mkTCP4(t, 1, 12345, 443, 0x1000, 0x9000, 0x10, 0, make([]byte, 1400))
	fin := mkTCP4(t, 2, 12345, 443, 0x1000+1400, 0x9000, 0x11, 0, make([]byte, 100)) // FIN|ACK
	after := mkTCP4(t, 3, 12345, 443, 0x1000+1500, 0x9000, 0x10, 0, make([]byte, 1400))
	var frames int
	o := newOffload(nil, func(p []byte) (int, error) { frames++; return len(p), nil })
	for _, p := range [][]byte{a, fin, after} {
		if _, err := o.write(p); err != nil {
			t.Fatal(err)
		}
	}
	if err := o.Flush(); err != nil {
		t.Fatal(err)
	}
	if frames != 2 {
		t.Fatalf("кадров %d, ожидалось 2 (склейка с FIN, потом одиночный)", frames)
	}
}

// TestOffloadCompletesPartialSum — ядро отдаёт пакеты СВОИХ сокетов с НЕПОЛНОЙ суммой: в поле лежит
// сумма псевдозаголовка, тело не просуммировано. Отдать такой пакет в туннель как есть значит
// отдать пиру пакет, который его же стек молча выбросит, — ровно тот отказ, который в этом проекте
// уже встречался на veth.
func TestOffloadCompletesPartialSum(t *testing.T) {
	p := mkTCP4(t, 7, 12345, 443, 0x2000, 0x9000, 0x18, 0, []byte("проверка суммы"))
	want := bytes.Clone(p)
	// Портим сумму так, как это делает ядро: кладём неполную.
	th := p[20:]
	binary.BigEndian.PutUint16(th[16:18], csum.FoldNoInv(
		csum.PseudoV4(p[12:16], p[16:20], 6, len(th))))
	f := make([]byte, vnetHdrLen+len(p))
	copy(f[vnetHdrLen:], p)
	f[0] = vnetNeedsCsum
	f[1] = vnetGSONone
	vnetPut(f[6:8], 20)
	vnetPut(f[8:10], 16)
	i := 0
	o := newOffload(func(b []byte) (int, error) {
		if i > 0 {
			return 0, ErrAgain
		}
		i++
		return copy(b, f), nil
	}, nil)
	got := readAll(t, o, 1)
	if !bytes.Equal(got[0], want) {
		t.Fatalf("сумма не достроена\nнадо:  %x\nвышло: %x", want, got[0])
	}
	if csum.TCPv4([4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, got[0][20:]) != 0 {
		t.Fatal("сумма готового сегмента не ноль")
	}
}
