//go:build linux

package link

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ПАЧКА НА ПРОВОДЕ ОБЯЗАНА БЫТЬ ТОЙ ЖЕ, ЧТО ПО ОДНОМУ, И ПРОВЕРИТЬ ЭТО МОЖНО ТОЛЬКО ПРОВОДОМ.
//
// В пакетной отправке две вещи, которые нельзя проверить рассуждением. Первая — раскладка struct
// mmsghdr: в x/sys её нет, поэтому она описана у нас, а естественное выравнивание Go должно совпасть
// с сишным (на 64-битных 56+4 с добивкой до 64, на 32-битных 28+4 без). Вторая — сумма TCP,
// сосчитанная по ДВУМ частям (свой заголовок и срез тела в записи) вместо непрерывного прохода.
//
// Ошибка в любой из двух даёт не отказ, а поток, который conntrack по дороге считает
// недействительным: правило «drop invalid» на любом промежуточном роутере тихо съест весь туннель.
// Такое ловится только сравнением байт, ушедших наружу.
//
// Стенд поэтому такой: настоящий сырой сокет отправляет одну и ту же запись двумя путями — пачкой и
// по одному, — а пакеты ловятся с провода сокетом AF_PACKET на устройстве, в которое они уходят.
// Сравниваются байты.
func TestПачкаНаПроводеТаЖе(t *testing.T) {
	// Устройство — ЛОКАЛЬНАЯ ПЕТЛЯ, а не заведённое стендом. Причина простая: dummy есть не везде
	// (на роутере OpenWrt модуля нет вовсе, и стенд там просто пропускался), а lo есть на любой
	// системе с сетью и настраивать его не нужно. Заодно так проверяется 32-битная раскладка
	// mmsghdr — тем же тестом на том же роутере.
	//
	// Пакеты при этом доставляются нашему же стеку, и на порт 443 он ответит RST. Это безвредно и
	// отфильтровано ниже по порту источника: свои сегменты мы узнаём по нему.
	const dev = "lo"
	ifi, err := net.InterfaceByName(dev)
	if err != nil {
		t.Skipf("пропущено: %v", err)
	}

	// Ловушка на исходящие кадры этого устройства.
	// ETH_P_ALL, а не ETH_P_IP: на исходящих кадрах устройства без соседа фильтр по типу протокола
	// не совпадает (проверено — сокет с ETH_P_IP не видит ни одного пакета), а нам нужны именно
	// исходящие. Чужое отбивается ниже по номеру протокола в заголовке IP.
	cap, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC,
		int(htons(unix.ETH_P_ALL)))
	if err != nil {
		t.Skipf("пропущено: AF_PACKET недоступен (%v)", err)
	}
	defer unix.Close(cap)
	if err := unix.Bind(cap, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_ALL), Ifindex: ifi.Index,
	}); err != nil {
		t.Skipf("пропущено: привязка ловушки (%v)", err)
	}

	daddr := [4]byte{127, 0, 0, 9}
	raw, err := OpenRawSend(daddr, [4]byte{})
	if err != nil {
		t.Skipf("пропущено: сырой сокет (%v)", err)
	}
	defer raw.Close()
	rl, ok := raw.(*rawLinux)
	if !ok {
		t.Fatal("сокет не тот")
	}

	// Запись из четырёх сегментов: столько же, сколько выходит у пачки кадров на живом MTU.
	const maxSeg = 400
	body := make([]byte, maxSeg*3+137)
	for i := range body {
		body[i] = byte(i*37 + 5)
	}
	hdrs := make([]byte, batchSegs*20)
	c := &Conn{
		raw: raw, SAddr: rl.Local(), DAddr: daddr, SPort: 40001, DPort: 443,
		seq: 1000, ack: 2000, state: StateEst, win: winFloor,
	}

	// --- путь пачкой ---
	drain(cap)
	var segs []Seglet
	for off, i := 0, 0; off < len(body); i++ {
		n := len(body) - off
		if n > maxSeg {
			n = maxSeg
		}
		h := hdrs[i*20 : i*20+20]
		c.fillHdrInto(h, c.seq+uint32(off), body[off:off+n])
		segs = append(segs, Seglet{Hdr: h, Body: body[off : off+n]})
		off += n
	}
	sent, err := rl.SendBatch(segs)
	if err != nil {
		t.Fatalf("пачка не ушла: %v", err)
	}
	if sent != len(segs) {
		t.Fatalf("ядро приняло %d сегментов из %d", sent, len(segs))
	}
	batch := grab(t, cap, len(segs), 40001)

	// --- путь по одному, теми же номерами ---
	drain(cap)
	c2 := &Conn{
		raw: raw, SAddr: rl.Local(), DAddr: daddr, SPort: 40001, DPort: 443,
		seq: 1000, ack: 2000, state: StateEst, win: winFloor,
	}
	one := make([]byte, 20+maxSeg)
	for off := 0; off < len(body); {
		n := len(body) - off
		if n > maxSeg {
			n = maxSeg
		}
		seg := one[:20+n]
		copy(seg[20:], body[off:off+n])
		c2.fillHdr(seg, c2.seq+uint32(off), n)
		if err := raw.Send(seg); err != nil {
			t.Fatalf("сегмент не ушёл: %v", err)
		}
		off += n
	}
	single := grab(t, cap, len(segs), 40001)

	if len(batch) != len(single) {
		t.Fatalf("пакетов: пачкой %d, по одному %d", len(batch), len(single))
	}
	for i := range batch {
		// Идентификатор IP ставит ядро, и он растёт: сравниваем всё, кроме него.
		a, b := clearIPID(batch[i]), clearIPID(single[i])
		if !bytes.Equal(a, b) {
			t.Fatalf("сегмент %d ушёл ДРУГИМИ байтами\nпачкой:    %x\nпо одному: %x", i, a, b)
		}
	}
	// И отдельно — сумма: она обязана сходиться на каждом пакете, иначе conntrack по дороге
	// пометит поток недействительным.
	for i, p := range batch {
		ihl := int(p[0]&0x0F) * 4
		if got := Csum(c.SAddr, daddr, p[ihl:]); got != 0 {
			t.Errorf("сегмент %d: сумма TCP не сошлась (%04x)", i, got)
		}
	}
}

func clearIPID(p []byte) []byte {
	out := bytes.Clone(p)
	if len(out) > 6 {
		out[4], out[5] = 0, 0
		// Сумма заголовка IP зависит от идентификатора — её тоже гасим.
		out[10], out[11] = 0, 0
	}
	return out
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func drain(fd int) {
	buf := make([]byte, 2048)
	for {
		if _, err := unix.Read(fd, buf); err != nil {
			return
		}
	}
}

func grab(t *testing.T, fd int, want int, sport uint16) [][]byte {
	t.Helper()
	var out [][]byte
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 4096)
	for len(out) < want && time.Now().Before(deadline) {
		n, err := unix.Read(fd, buf)
		if err == unix.EAGAIN {
			time.Sleep(2 * time.Millisecond)
			continue
		}
		if err != nil {
			t.Fatalf("чтение ловушки: %v", err)
		}
		if n < 40 || buf[9] != 6 {
			continue
		}
		ihl := int(buf[0]&0x0F) * 4
		if n < ihl+20 {
			continue
		}
		// Только СВОИ сегменты: по петле идёт и ответ нашего же стека (RST на закрытый порт).
		if binary.BigEndian.Uint16(buf[ihl:ihl+2]) != sport {
			continue
		}
		out = append(out, bytes.Clone(buf[:n]))
	}
	if len(out) != want {
		t.Fatalf("поймано %d пакетов из %d", len(out), want)
	}
	return out
}
