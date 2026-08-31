//go:build linux

package tun

import (
	"bufio"
	"encoding/binary"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xyzmean/xsteer/csum"
)

// ЯДРО КАК СУДЬЯ, ЧАСТЬ ПЕРВАЯ: кадр вообще доходит до стека TCP.
//
// Склеенный кадр отдаётся настоящему устройству и адресуется ЗАКРЫТОМУ порту на его же адресе:
// ядро обязано ответить RST. Приращение OutRsts доказывает, что метаданные virtio, длина в
// заголовке IP и его сумма верны — при ошибке в любом из трёх кадр умирает в ip_rcv молча.
//
// ЧЕГО ЭТА ПРОВЕРКА НЕ ДОКАЗЫВАЕТ, И ЭТО ВАЖНО ЗНАТЬ. Неполную сумму TCP она НЕ проверяет вовсе:
// на приёме ядро считает CHECKSUM_PARTIAL признаком «сумма не нужна» (skb_csum_unnecessary), и
// нарочно испорченное поле проходит здесь так же успешно, как верное — проверено. Судьёй для суммы
// служит второй тест ниже, где ядро кадр действительно РЕЖЕТ.
func TestOffloadFrameReachesStack(t *testing.T) {
	const dev = "xs-gso-check"
	d, err := openOne(dev, false, true)
	if err != nil {
		t.Skipf("пропущено: TUNSETIFF недоступен (%v) — нужны /dev/net/tun и CAP_NET_ADMIN", err)
	}
	defer d.Close()
	ld := d.(*linuxDev)
	if ld.off == nil {
		t.Skipf("пропущено: разгрузка сегментации не встала (%s)", ld.offWhy)
	}
	if out, err := exec.Command("ip", "addr", "replace", "10.213.0.1/24", "dev", dev).CombinedOutput(); err != nil {
		t.Skipf("пропущено: не удалось задать адрес (%v: %s)", err, out)
	}
	if out, err := exec.Command("ip", "link", "set", dev, "up").CombinedOutput(); err != nil {
		t.Skipf("пропущено: не удалось поднять устройство (%v: %s)", err, out)
	}

	// Порт назначения заведомо закрыт: на него никто не слушает, и ядро отвечает RST.
	const dport = 9

	before := snmp(t)
	// Пять сегментов одного потока подряд — то, что склеивается в один супер-кадр.
	seq := uint32(0x30000)
	for i := 0; i < 5; i++ {
		body := make([]byte, 1400)
		for j := range body {
			body[j] = byte(i + j)
		}
		flags := byte(0x10)
		if i == 4 {
			flags = 0x18
		}
		p := mkLocalTCP(uint16(500+i), 45000, dport, seq, 1, flags, body)
		if _, err := d.Write(p); err != nil {
			t.Fatalf("запись пакета %d: %v", i, err)
		}
		seq += uint32(len(body))
	}
	if err := d.Flush(); err != nil {
		t.Fatalf("сброс: %v", err)
	}
	// Ядро обрабатывает кадр в своей мягкой очереди прерываний, а не в нашем вызове.
	time.Sleep(200 * time.Millisecond)
	after := snmp(t)

	if got := after["OutRsts"] - before["OutRsts"]; got == 0 {
		t.Fatal("ядро не ответило ни одним RST: склеенный кадр до стека TCP не дошёл вовсе " +
			"(проверьте длину в заголовке IP и его сумму)")
	}
}

// mkLocalTCP — сегмент от 10.213.0.9 к 10.213.0.1 с верными обеими суммами.
func mkLocalTCP(id, sport, dport uint16, seq, ack uint32, flags byte, body []byte) []byte {
	p := make([]byte, 40+len(body))
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:6], id)
	p[6] = 0x40
	p[8] = 64
	p[9] = 6
	copy(p[12:16], []byte{10, 213, 0, 9})
	copy(p[16:20], []byte{10, 213, 0, 1})
	binary.BigEndian.PutUint16(p[10:12], ipCsum(p[:20]))
	th := p[20:]
	binary.BigEndian.PutUint16(th[0:2], sport)
	binary.BigEndian.PutUint16(th[2:4], dport)
	binary.BigEndian.PutUint32(th[4:8], seq)
	binary.BigEndian.PutUint32(th[8:12], ack)
	th[12] = 5 << 4
	th[13] = flags
	binary.BigEndian.PutUint16(th[14:16], 64000)
	copy(th[20:], body)
	binary.BigEndian.PutUint16(th[16:18], tcpCsum(p[12:16], p[16:20], th))
	return p
}

func ipCsum(h []byte) uint16 { return csum.Of(h) }

func tcpCsum(saddr, daddr, th []byte) uint16 {
	return csum.Fold(csum.PseudoV4(saddr, daddr, 6, len(th)) + csum.Sum(th))
}

// snmp читает счётчики из /proc/net/snmp и /proc/net/netstat по именам столбцов.
func snmp(t *testing.T) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, path := range []string{"/proc/net/snmp", "/proc/net/netstat"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		var names []string
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 2 {
				continue
			}
			if names != nil && len(names) == len(fields) && names[0] == fields[0] {
				for i := 1; i < len(fields); i++ {
					v, err := strconv.ParseInt(fields[i], 10, 64)
					if err == nil {
						out[names[i]] = v
					}
				}
				names = nil
				continue
			}
			names = fields
		}
		f.Close()
	}
	return out
}

// ЯДРО КАК СУДЬЯ, ЧАСТЬ ВТОРАЯ: неполная сумма, оставленная устройству, верна.
//
// ЗАЧЕМ ОТДЕЛЬНЫЙ СТЕНД. Достраивает эту сумму не наш код, поэтому вектором её не проверить, а
// приёмный путь ядра её не смотрит (см. выше). Единственный способ узнать правду — заставить ядро
// кадр НАРЕЗАТЬ: тогда оно правит поле на длину каждого сегмента (tcp_gso_segment) и достраивает
// нагрузкой (skb_checksum_help), ровно как сделала бы микросхема.
//
// Стенд поэтому такой: два устройства. В первое (с разгрузкой) мы пишем склеенный кадр, адресуя его
// в сеть второго; второе открыто БЕЗ разгрузки, значит ядро обязано порезать кадр перед выдачей —
// и отдаёт нам сегменты с ПОЛНЫМИ суммами. Их мы и проверяем.
//
// Проверено, что стенд ловит: испорченное поле неполной суммы даёт здесь сегменты с несошедшейся
// суммой, то есть тест падает.
func TestOffloadPartialSumSurvivesKernelSegmentation(t *testing.T) {
	const devA, devB = "xs-gso-a", "xs-gso-b"
	a, err := openOne(devA, false, true)
	if err != nil {
		t.Skipf("пропущено: TUNSETIFF недоступен (%v)", err)
	}
	defer a.Close()
	if a.(*linuxDev).off == nil {
		t.Skipf("пропущено: разгрузка не встала (%s)", a.(*linuxDev).offWhy)
	}
	// Второе устройство БЕЗ разгрузки — в этом весь смысл: ядро обязано порезать кадр само.
	b, err := openOne(devB, false, false)
	if err != nil {
		t.Skipf("пропущено: второе устройство не открылось (%v)", err)
	}
	defer b.Close()
	for _, args := range [][]string{
		{"addr", "replace", "10.213.0.1/24", "dev", devA},
		{"link", "set", devA, "up"},
		{"addr", "replace", "10.214.0.1/24", "dev", devB},
		{"link", "set", devB, "up"},
	} {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Skipf("пропущено: ip %v (%v: %s)", args, err, out)
		}
	}
	restore := setSysctl(t, "/proc/sys/net/ipv4/ip_forward", "1")
	defer restore()
	// Обратного маршрута к 10.213.0.9 нет ниоткуда, кроме devA, поэтому строгая проверка источника
	// пропустила бы и так; выключаем на всякий случай — иначе пропуск теста выглядел бы как отказ.
	defer setSysctl(t, "/proc/sys/net/ipv4/conf/"+devA+"/rp_filter", "0")()

	const gso = 1400
	segs := 4
	seq := uint32(0x40000)
	want := make([]byte, 0, segs*gso)
	for i := 0; i < segs; i++ {
		body := make([]byte, gso)
		for j := range body {
			body[j] = byte(i*13 + j)
		}
		want = append(want, body...)
		flags := byte(0x10)
		if i == segs-1 {
			flags = 0x18
		}
		p := mkFwdTCP(uint16(700+i), 45001, 80, seq, 1, flags, body)
		if _, err := a.Write(p); err != nil {
			t.Fatalf("запись %d: %v", i, err)
		}
		seq += uint32(len(body))
	}
	if err := a.Flush(); err != nil {
		t.Fatalf("сброс: %v", err)
	}

	// Читаем то, что ядро нарезало и отдало второму устройству.
	got := make([]byte, 0, len(want))
	buf := make([]byte, 2048)
	deadline := time.Now().Add(2 * time.Second)
	for len(got) < len(want) && time.Now().Before(deadline) {
		ok, err := b.WaitRead(200 * time.Millisecond)
		if err != nil {
			t.Fatalf("ожидание на втором устройстве: %v", err)
		}
		if !ok {
			continue
		}
		n, err := b.Read(buf)
		if err != nil {
			continue
		}
		p := buf[:n]
		if n < 40 || p[0]>>4 != 4 || p[9] != 6 {
			continue
		}
		th := p[20:]
		// ВОТ ОНА, ПРОВЕРКА: сумма готового сегмента обязана давать ноль. Если поле неполной суммы
		// в склеенном кадре было неверным, ядро правило неверное число — и здесь это видно.
		if s := tcpCsum2(p[12:16], p[16:20], th); s != 0 {
			t.Fatalf("сегмент на %d байт: сумма TCP не сошлась (%04x) — неполная сумма в "+
				"склеенном кадре неверна", n, s)
		}
		got = append(got, th[int(th[12]>>4)*4:]...)
	}
	if len(got) != len(want) {
		t.Fatalf("ядро отдало %d байт нагрузки из %d — кадр порезан не целиком", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("байт %d разошёлся после нарезки ядром", i)
		}
	}
}

// mkFwdTCP — сегмент из сети первого устройства в сеть второго: его ядро обязано переслать.
func mkFwdTCP(id, sport, dport uint16, seq, ack uint32, flags byte, body []byte) []byte {
	p := mkLocalTCP(id, sport, dport, seq, ack, flags, body)
	copy(p[16:20], []byte{10, 214, 0, 9})
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:12], ipCsum(p[:20]))
	th := p[20:]
	th[16], th[17] = 0, 0
	binary.BigEndian.PutUint16(th[16:18], tcpCsum(p[12:16], p[16:20], th))
	return p
}

// tcpCsum2 — сумма над готовым сегментом: ноль означает «сошлась».
func tcpCsum2(saddr, daddr, th []byte) uint16 {
	return csum.Fold(csum.PseudoV4(saddr, daddr, 6, len(th)) + csum.Sum(th))
}

// setSysctl задаёт значение и возвращает функцию, возвращающую прежнее.
func setSysctl(t *testing.T, path, val string) func() {
	t.Helper()
	old, err := os.ReadFile(path)
	if err != nil {
		return func() {}
	}
	if err := os.WriteFile(path, []byte(val), 0o644); err != nil {
		t.Skipf("пропущено: не удалось задать %s (%v)", path, err)
	}
	return func() { _ = os.WriteFile(path, old, 0o644) }
}
