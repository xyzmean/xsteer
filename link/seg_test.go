// Сборка и разбор сегмента: те же случаи, что в tests/obfsmatch.c движка на C. Сумма и арифметика
// подтверждений проверяются здесь, потому что ошибка в них не видна как ошибка — пакеты просто
// начинают исчезать по дороге, а виноватой выглядит сеть.
package link

import (
	"math/rand"
	"testing"
)

var (
	src = [4]byte{192, 168, 1, 5}
	dst = [4]byte{203, 0, 113, 7}
)

// ipWrap оборачивает сегмент в заголовок IPv4 — так, как его отдаёт сырой сокет на приёме.
func ipWrap(seg []byte, s, d [4]byte) []byte {
	total := 20 + len(seg)
	p := make([]byte, total)
	p[0] = 0x45
	p[2], p[3] = byte(total>>8), byte(total)
	p[8] = 64
	p[9] = 6
	copy(p[12:16], s[:])
	copy(p[16:20], d[:])
	copy(p[20:], seg)
	return p
}

func TestКругСборкиИРазбора(t *testing.T) {
	payload := []byte("нагрузка, которая обязана дойти без единого изменения")
	buf := make([]byte, 60+len(payload))
	n := BuildSeg(buf, src, dst, 41234, 443, 0x11223344, 0x55667788, PSH|ACK, OptNone, payload)
	if n != 20+len(payload) {
		t.Fatalf("сегмент данных вышел %d байт при заголовке 20 и нагрузке %d", n, len(payload))
	}
	// Готовый сегмент обязан давать нулевую сумму: это и есть проверка того, что мы посчитали её
	// так же, как посчитает получатель.
	if Csum(src, dst, buf[:n]) != 0 {
		t.Fatal("сумма собранного сегмента не сходится")
	}
	s, ok := ParseSeg(ipWrap(buf[:n], src, dst))
	if !ok {
		t.Fatal("свой же сегмент не разобрался")
	}
	if s.SPort != 41234 || s.DPort != 443 {
		t.Errorf("порты разобраны как %d → %d", s.SPort, s.DPort)
	}
	if s.Seq != 0x11223344 || s.Ack != 0x55667788 {
		t.Error("номера разобраны неверно")
	}
	if s.Flags != PSH|ACK {
		t.Errorf("флаги %02x", s.Flags)
	}
	if string(s.Payload) != string(payload) {
		t.Error("нагрузка испортилась")
	}
	if s.SAddr != src || s.DAddr != dst {
		t.Error("адреса разобраны неверно")
	}
}

func TestОпцииТолькоВSYN(t *testing.T) {
	buf := make([]byte, 60)
	n := BuildSeg(buf, src, dst, 41234, 443, 1000, 0, SYN, OptScale, nil)
	// 32 байта: 20 заголовка и 12 опций — ровно как у Windows. Набор и порядок опций в SYN это
	// отпечаток стека, и сверен он с настоящим трафиком, а не выдуман.
	if n != 32 {
		t.Fatalf("SYN обязан быть 32 байта (виндовый профиль опций), а вышел %d", n)
	}
	if buf[12]>>4 != 8 {
		t.Errorf("длина заголовка в словах = %d", buf[12]>>4)
	}
	// MSS: опция 2 длиной 4. SYN совсем без опций сам по себе признак — потому она и есть.
	if buf[20] != 2 || buf[21] != 4 {
		t.Error("опции MSS нет")
	}
	if got := int(buf[22])<<8 | int(buf[23]); got != 1460 {
		t.Errorf("MSS = %d", got)
	}
	// Масштаб окна: NOP для выравнивания, затем опция 3 длиной 3. Без него conntrack по дороге
	// держал бы нас в 64 КиБ в полёте — измерено как 10,2 Мбит/с на круге 50 мс.
	if buf[24] != 1 || buf[25] != 3 || buf[26] != 3 || buf[27] != WScale {
		t.Errorf("опции масштаба окна нет или она не та: % x", buf[24:28])
	}
	// Разрешение SACK: NOP, NOP, опция 4 длиной 2. Его посылают все современные стеки, и его
	// отсутствие видно первым же пакетом соединения — этот признак нашёлся сравнением с настоящим
	// трафиком xhttp.
	if buf[28] != 1 || buf[29] != 1 || buf[30] != 4 || buf[31] != 2 {
		t.Errorf("разрешения SACK нет или оно не то: % x", buf[28:32])
	}
	if Csum(src, dst, buf[:n]) != 0 {
		t.Fatal("сумма SYN с опциями не сходится")
	}
	// Сегмент данных опций не несёт вовсе: они стоили бы байт на каждом пакете. Именно поэтому мы
	// и не объявляем метки времени — их пришлось бы ставить в каждый сегмент, и 61 байт накладных
	// стал бы 73.
	n2 := BuildSeg(buf, src, dst, 41234, 443, 1000, 2000, PSH|ACK, OptNone, []byte("x"))
	if n2 != 21 {
		t.Errorf("сегмент данных вышел %d байт вместо 21 — в нём опции", n2)
	}
}

func TestРазборОтвергаетЧужое(t *testing.T) {
	buf := make([]byte, 60)
	n := BuildSeg(buf, src, dst, 41234, 443, 1, 1, ACK, OptNone, nil)
	good := ipWrap(buf[:n], src, dst)

	if _, ok := ParseSeg(good[:19]); ok {
		t.Error("обрезок принят")
	}
	notIP4 := append([]byte(nil), good...)
	notIP4[0] = 0x65
	if _, ok := ParseSeg(notIP4); ok {
		t.Error("не IPv4 принят")
	}
	notTCP := append([]byte(nil), good...)
	notTCP[9] = 17
	if _, ok := ParseSeg(notTCP); ok {
		t.Error("не TCP принят")
	}
	// Битая сумма ПОМЕЧАЕТСЯ, но не отвергает сегмент: целостность обеспечивает AEAD, а сегменты
	// от обычного стека TCP через veth и loopback приходят с незавершённой суммой (разгрузка).
	// Отвергай мы их — хаб не видел бы ни одного постороннего клиента TLS на той же машине, то
	// есть дорожка неопознанных не работала бы вовсе.
	badSum := append([]byte(nil), good...)
	badSum[20+16] ^= 0xFF
	bs, ok := ParseSeg(badSum)
	if !ok {
		t.Error("сегмент с битой суммой отвергнут — тогда зондировщика хаб не увидит")
	}
	if bs.CsumOK {
		t.Error("битая сумма не помечена — счётчик порчи на пути станет бесполезен")
	}
	if gs, _ := ParseSeg(good); !gs.CsumOK {
		t.Error("верная сумма помечена как битая")
	}
	shortHdr := append([]byte(nil), good...)
	shortHdr[20+12] = 3 << 4 // длина заголовка меньше минимальной
	if _, ok := ParseSeg(shortHdr); ok {
		t.Error("заголовок короче 20 байт принят")
	}
	// Порча каждого байта: ни одной паники (сюда приходит что угодно из сети).
	for i := range good {
		for _, d := range []byte{1, 0x80, 0xFF} {
			bad := append([]byte(nil), good...)
			bad[i] ^= d
			_, _ = ParseSeg(bad)
		}
	}
}

func TestСуммаНаВсехДлинах(t *testing.T) {
	// Нечётная длина нагрузки — отдельный случай в подсчёте (последний байт идёт в старшую
	// половину слова), и ошибка в нём даёт битую сумму на половине пакетов.
	rng := rand.New(rand.NewSource(4))
	for plen := 0; plen < 300; plen++ {
		pay := make([]byte, plen)
		rng.Read(pay)
		buf := make([]byte, 60+plen)
		n := BuildSeg(buf, src, dst, 40000, 443, rng.Uint32(), rng.Uint32(), PSH|ACK, OptNone, pay)
		if Csum(src, dst, buf[:n]) != 0 {
			t.Fatalf("длина нагрузки %d: сумма не сходится", plen)
		}
		s, ok := ParseSeg(ipWrap(buf[:n], src, dst))
		if !ok || string(s.Payload) != string(pay) {
			t.Fatalf("длина нагрузки %d: круг не сошёлся", plen)
		}
	}
}

func TestПодтверждениеТолькоВперёд(t *testing.T) {
	if got := NextAck(1000, 1000, 100); got != 1100 {
		t.Errorf("подтверждение по порядку = %d", got)
	}
	// Старый сегмент не должен тянуть подтверждение назад: для conntrack это выглядело бы как
	// повторная передача старого, и он начал бы считать наш поток недействительным.
	if got := NextAck(1100, 900, 50); got != 1100 {
		t.Errorf("старый сегмент сдвинул подтверждение на %d", got)
	}
	// Через заворот uint32 — «позже» определяется знаковой разностью, а не сравнением чисел.
	if got := NextAck(0xFFFFFFF0, 0xFFFFFFF0, 0x20); got != 0x10 {
		t.Errorf("через заворот получилось %08x", got)
	}
	if got := NextAck(0x10, 0xFFFFFF00, 0x10); got != 0x10 {
		t.Errorf("старый сегмент за заворотом сдвинул подтверждение на %08x", got)
	}
}
