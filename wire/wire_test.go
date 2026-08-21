// Проверки арифметики провода. Случаи те же, что в tests/xswirematch.c движка на C, — и это
// не дублирование ради дублирования: две реализации одного протокола обязаны отвечать
// одинаково, а «обязаны» и «отвечают» — разные утверждения. Расхождение здесь означало бы
// десктопный клиент, который поднимает туннель к тому же хабу и не несёт трафик.
package wire

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
)

func TestРазмеры(t *testing.T) {
	if Overhead != 61 {
		t.Fatalf("накладные расходы %d, а не 61 байт", Overhead)
	}
	if HdrRoom != 45 {
		t.Fatalf("место под заголовки %d, а не 45", HdrRoom)
	}
	if MTUDefault != 1439 {
		t.Fatalf("MTU при канале 1500 = %d, а не 1439", MTUDefault)
	}
	if HdrRoom+MTUDefault+Tag != LinkMax {
		t.Fatal("строка буфера не равна пакету на проводе")
	}
	// Ради этих одиннадцати байт протокол и затевался: столько xsteer выигрывает у WireGuard,
	// который в том же движке уже едет поверх поддельного TCP.
	if 72-Overhead != 11 {
		t.Fatal("выигрыш против WireGuard поверх поддельного TCP перестал быть 11 байт")
	}
	for _, c := range []struct{ link, want int }{{1500, 1439}, {1492, 1431}, {1400, 1339}} {
		if got := MTU(c.link); got != c.want {
			t.Errorf("MTU(%d) = %d, ждали %d", c.link, got, c.want)
		}
	}
}

func TestЗапись(t *testing.T) {
	var h [RecHdr]byte
	if err := RecBuild(h[:], 1455); err != nil {
		t.Fatal(err)
	}
	if h[0] != 0x17 {
		t.Error("тип записи не application_data")
	}
	if h[1] != 0x03 || h[2] != 0x03 {
		t.Error("версия записи не 0x0303 — на проводе это отличие от всякого TLS 1.3")
	}
	if got := int(h[3])<<8 | int(h[4]); got != 1455 {
		t.Errorf("длина записана как %d", got)
	}
	if RecBuild(h[:], Tag-1) == nil {
		t.Error("нагрузка короче тега принята")
	}
	if RecBuild(h[:], 0x10000) == nil {
		t.Error("нагрузка больше поля длины принята")
	}

	seg := make([]byte, RecHdr+100)
	if err := RecBuild(seg, 100); err != nil {
		t.Fatal(err)
	}
	for i := RecHdr; i < len(seg); i++ {
		seg[i] = byte(i)
	}
	body, err := RecParse(seg)
	if err != nil || len(body) != 100 || !bytes.Equal(body, seg[RecHdr:]) {
		t.Fatalf("разбор целой записи не удался: %v", err)
	}

	bad := append([]byte(nil), seg...)
	bad[0] = 0x16
	if _, err := RecParse(bad); err == nil {
		t.Error("чужой тип записи принят")
	}
	bad = append([]byte(nil), seg...)
	bad[2] = 0x04
	if _, err := RecParse(bad); err == nil {
		t.Error("версия 0x0304 принята")
	}
	bad = append([]byte(nil), seg...)
	bad[4] = 99
	if _, err := RecParse(bad); err == nil {
		t.Error("длина меньше остатка принята — за концом записи можно было бы спрятать байты")
	}
	bad[4] = 101
	if _, err := RecParse(bad); err == nil {
		t.Error("длина больше остатка принята")
	}
	if _, err := RecParse(seg[:RecMin-1]); err == nil {
		t.Error("сегмент короче минимальной записи принят")
	}

	// Keepalive: открытый текст пустой, на проводе остаётся только тег.
	ka := make([]byte, RecHdr+Tag)
	if err := RecBuild(ka, Tag); err != nil {
		t.Fatal(err)
	}
	if body, err := RecParse(ka); err != nil || len(body) != Tag {
		t.Fatal("keepalive не разобрался")
	}
}

func TestТипКадра(t *testing.T) {
	p := make([]byte, 64)
	if FrameKind(nil) != KindKeepalive {
		t.Error("пустой кадр — это keepalive")
	}
	p[0] = 0x45
	if FrameKind(p[:40]) != KindIPv4 {
		t.Error("0x45 должен быть IPv4")
	}
	if FrameKind(p[:19]) != KindBad {
		t.Error("IPv4 короче заголовка обязан быть браком")
	}
	p[0] = 0x60
	if FrameKind(p[:40]) != KindIPv6 {
		t.Error("0x60 должен быть IPv6")
	}
	if FrameKind(p[:39]) != KindBad {
		t.Error("IPv6 короче заголовка обязан быть браком")
	}
	p[0] = CtlProbe
	if FrameKind(p[:8]) != KindCtl {
		t.Error("младшие значения — служебный кадр")
	}
	p[0] = 0x50
	if FrameKind(p[:40]) != KindBad {
		t.Error("чужая версия IP обязана быть браком")
	}
}

func TestСмещениеИNonce(t *testing.T) {
	const isn = 0xFFFFFFF0
	if Rel(isn+1, isn) != 1 {
		t.Error("первая запись обязана иметь смещение 1")
	}
	// Заворот: 2 - 0xFFFFFFF0 = 18. Считать это надо без ветвлений на «а вдруг перевернулось»
	// — беззнаковая арифметика даёт верный ответ сама, и именно на неё опирается обе стороны.
	if Rel(2, isn) != 18 {
		t.Errorf("смещение через заворот uint32 посчитано как %d", Rel(2, isn))
	}
	// Инвариантность к постоянному сдвигу: без неё утверждение про межсетевые экраны,
	// рандомизирующие начальный номер, остаётся словами.
	for _, delta := range []uint32{1, 12345, 0x80000000, 0xFFFFFFFF} {
		for i := uint32(1); i < 2000; i++ {
			if Rel(isn+i, isn) != Rel(isn+i+delta, isn+delta) {
				t.Fatalf("сдвиг номеров на %d изменил смещение", delta)
			}
		}
	}

	var iv [12]byte
	for i := range iv {
		iv[i] = byte(0xA0 + i)
	}
	if got := Nonce(iv, 0); got != iv {
		t.Error("нулевое смещение обязано оставить iv нетронутым")
	}
	got := Nonce(iv, 1)
	if got[11] != iv[11]^1 {
		t.Error("единица обязана лечь в младший байт")
	}
	if !bytes.Equal(got[:8], iv[:8]) {
		t.Error("старшие байты iv тронуты — это уже не раскладка TLS 1.3")
	}
	// Независимый подсчёт по правилу RFC 8446 §5.3 для 64-битного номера: у нас номер
	// 32-битный, и результат обязан совпасть с ним на всём диапазоне младших разрядов.
	for _, rel := range []uint32{1, 255, 256, 65535, 1 << 24, 0x7FFFFFFF, 0xFFFFFFFF} {
		want := iv
		seq := uint64(rel)
		for i := 0; i < 8; i++ {
			want[11-i] ^= byte(seq >> (8 * i))
		}
		if Nonce(iv, rel) != want {
			t.Fatalf("nonce разошёлся с выводом TLS 1.3 на смещении %d", rel)
		}
	}
}

func TestОкноПриёма(t *testing.T) {
	var w Window
	if w.Check(0) {
		t.Error("нулевое смещение не бывает данными")
	}
	if !w.Check(1) {
		t.Error("первая запись обязана быть принята")
	}
	w.Commit(1)
	if w.Check(1) {
		t.Error("повтор первой записи принят")
	}
	if !w.Check(1460) {
		t.Error("следующая по порядку отвергнута")
	}
	w.Commit(1460)
	if !w.Check(5000) {
		t.Error("пропуск вперёд отвергнут")
	}
	w.Commit(5000)
	if !w.Check(2920) {
		t.Error("пришедшая позже дырка отвергнута")
	}
	w.Commit(2920)
	if w.Check(2920) {
		t.Error("повтор дырки принят")
	}
	if w.max != 5000 {
		t.Errorf("самое дальнее принятое сдвинулось назад: %d", w.max)
	}

	// Разделение проверки и фиксации: подделанный пакет с далёким смещением не обязан
	// выбивать из окна честный поток. Ровно ради этого Check и Commit разные функции.
	w = Window{}
	for r := uint32(1); r <= 100; r++ {
		if w.Check(r) {
			w.Commit(r)
		}
	}
	w.Check(900000000) // тег не сошёлся — Commit не зовём
	if w.max != 100 {
		t.Errorf("неподтверждённое смещение сдвинуло max на %d", w.max)
	}
	if !w.Check(101) {
		t.Error("честный следующий пакет отвергнут после попытки подделки")
	}

	// Память кольца: что старше него — отвергается, потому что проверить нечем.
	w = Window{}
	for r := uint32(1); r <= WinRing+50; r++ {
		if w.Check(r) {
			w.Commit(r)
		}
	}
	if w.Check(3) {
		t.Error("смещение за пределами памяти принято")
	}
	if w.Check(WinRing + 10) {
		t.Error("повтор внутри памяти принят")
	}
	if !w.Check(WinRing + 51) {
		t.Error("новое смещение отвергнуто")
	}

	// Поток с переупорядочиванием и дублями: ни одного принятого дубля и ни одного ложного
	// отказа внутри памяти кольца.
	w = Window{}
	rng := rand.New(rand.NewSource(1))
	seen := map[uint32]bool{}
	var offs []uint32
	for r := uint32(1); r <= 20000; r++ {
		offs = append(offs, r)
	}
	// Локальная перестановка на ±40 записей — то, что даёт настоящая сеть.
	for i := range offs {
		j := i + rng.Intn(41) - 20
		if j >= 0 && j < len(offs) {
			offs[i], offs[j] = offs[j], offs[i]
		}
	}
	dupAccepted, falseReject := 0, 0
	for i, off := range offs {
		ok := w.Check(off)
		if ok {
			w.Commit(off)
			if seen[off] {
				dupAccepted++
			}
			seen[off] = true
		} else if !seen[off] && int32(off-w.max) > -int32(WinRing/2) {
			falseReject++
		}
		if i%7 == 0 { // каждый седьмой шлём повторно
			if w.Check(off) {
				w.Commit(off)
				dupAccepted++
			}
		}
	}
	if dupAccepted != 0 {
		t.Errorf("принято дублей: %d", dupAccepted)
	}
	if falseReject != 0 {
		t.Errorf("ложных отказов внутри памяти: %d", falseReject)
	}
}

func TestРетайр(t *testing.T) {
	if RetireDue(1000, 1000) {
		t.Error("на покое ретайр сработал")
	}
	if !RetireDue(RelRetire, 0) {
		t.Error("ретайр по объёму не сработал")
	}
	if RetireDue(RelRetire-1, 0) {
		t.Error("ретайр сработал за байт до порога")
	}
	if !RetireDue(0, AgeRetireMS) {
		t.Error("ретайр по времени не сработал")
	}
	if !RenewDue(RelRetire/100*95, 0) {
		t.Error("успешник не поднимается на 95% объёма")
	}
	if RenewDue(RelRetire/100*80, 0) {
		t.Error("успешник поднялся на 80% объёма — слишком рано")
	}
	if !RenewDue(0, AgeRetireMS/100*95) {
		t.Error("успешник не поднимается на 95% времени")
	}
	// Успешник ОБЯЗАН быть раньше ретайра на всём диапазоне: иначе соединение замолчит, не
	// подготовив смену, и туннель встанет на время нового рукопожатия.
	for rel := uint32(0); rel < RelRetire; rel += RelRetire / 1000 {
		if RetireDue(rel, 0) && !RenewDue(rel, 0) {
			t.Fatalf("на смещении %d ретайр наступил раньше успешника", rel)
		}
	}
}

func TestПоискMTU(t *testing.T) {
	if got := MTUNext(MTUFloor, 0, 1431); got != 1431 {
		t.Errorf("без верхней границы обязаны пробовать потолок, а пробуем %d", got)
	}
	if got := MTUNext(1431, 0, 1431); got != 0 {
		t.Errorf("потолок подтверждён — проверять нечего, а вернулось %d", got)
	}
	if got := MTUNext(MTUFloor, 0, 9000); got != MTUDefault {
		t.Errorf("потолок обязан быть зажат пределом записи, а вернулось %d", got)
	}
	if got := MTUNext(1400, 0, 1300); got != 0 {
		t.Errorf("потолок ниже низа — нечего проверять, а вернулось %d", got)
	}
	if got := MTUNext(1200, 1400, 1431); got != 1300 {
		t.Errorf("середина отрезка = %d", got)
	}
	if got := MTUNext(1380, 1387, 1431); got != 0 {
		t.Errorf("разница меньше зерна — обязано сойтись, а вернулось %d", got)
	}

	// Полный перебор настоящих пределов: поиск обязан сойтись в пределах зерна, ни разу не
	// выбрав размер больше настоящего, и уложиться в предел числа проб.
	worst := 0
	for real := MTUFloor; real <= MTUDefault; real++ {
		lo, hi, tries := MTUFloor, 0, 0
		for {
			next := MTUNext(lo, hi, MTUDefault)
			if next == 0 {
				break
			}
			tries++
			if tries > MTUTriesMax {
				t.Fatalf("предел %d: поиск не уложился в %d проб", real, MTUTriesMax)
			}
			if next <= real {
				lo = next
			} else {
				hi = next
			}
		}
		if lo > real {
			t.Fatalf("предел %d: поиск выбрал больший размер %d — это чёрная дыра на пути", real, lo)
		}
		if real-lo > MTUGrain {
			t.Fatalf("предел %d: сошлись на %d, потеряно %d байт", real, lo, real-lo)
		}
		if tries > worst {
			worst = tries
		}
	}
	if worst > MTUTriesMax {
		t.Fatalf("худший случай потребовал %d проб", worst)
	}
}

func TestСлужебныеКадры(t *testing.T) {
	pt := make([]byte, MTUDefault+16)
	const size = 1400
	n, ok := ProbeBuild(pt, size)
	if !ok || n != size {
		t.Fatal("проба не собралась заявленного размера")
	}
	if FrameKind(pt[:size]) != KindCtl {
		t.Error("проба обязана быть служебным кадром")
	}
	if ProbeSize(pt[:size]) != size {
		t.Error("размер пробы не читается обратно")
	}
	if ProbeSize(pt[:100]) != -1 {
		t.Error("кадр, заявивший больше, чем пришло, принят за пробу — эхо на него солгало бы")
	}
	if _, ok := ProbeBuild(pt, 3); ok {
		t.Error("слишком маленькая проба собралась")
	}
	if _, ok := ProbeBuild(pt, MTUDefault+1); ok {
		t.Error("проба больше предела записи собралась")
	}

	if PackBuild(pt, size) != 3 {
		t.Error("эхо обязано быть тремя байтами")
	}
	if PackSize(pt[:3]) != size {
		t.Error("размер из эха не читается")
	}
	if ProbeSize(pt[:3]) != -1 {
		t.Error("эхо выдано за пробу")
	}
	if MTUBuild(pt, 1387) != 3 {
		t.Error("итог обязан быть тремя байтами")
	}
	if MTUValue(pt[:3]) != 1387 {
		t.Error("значение итога не читается")
	}
	if PackSize(pt[:3]) != -1 {
		t.Error("итог выдан за эхо")
	}
}

func TestОграничительЧастоты(t *testing.T) {
	var r RateLog
	ok, held := r.Allow(1000, LogEveryMS)
	if !ok || held != 0 {
		t.Fatal("первое сообщение обязано печататься без подавленных")
	}
	printed := 0
	for now := int64(1001); now <= 5999; now++ {
		if ok, _ := r.Allow(now, LogEveryMS); ok {
			printed++
		}
	}
	if printed != 0 {
		t.Errorf("внутри окна напечатано %d строк", printed)
	}
	ok, held = r.Allow(6001, LogEveryMS)
	if !ok {
		t.Fatal("за окном обязано печатать снова")
	}
	if held != 4999 {
		t.Errorf("подавленных посчитано %d, а не 4999 — ограничитель врёт о числе попыток", held)
	}
	if ok, _ := r.Allow(6002, LogEveryMS); ok {
		t.Error("сразу после печати обязан молчать")
	}
	if HeldSuffix(0) != "" {
		t.Error("при нуле подавленных хвоста быть не должно")
	}
	if HeldSuffix(7) == "" {
		t.Error("подавленные обязаны попасть в строку")
	}
}

func TestПачкаКадров(t *testing.T) {
	frames := [][]byte{
		bytes.Repeat([]byte{0x45}, 40),
		bytes.Repeat([]byte{0x46}, 1439),
		{0x47},
	}
	dst := make([]byte, MTUDefault*8)
	n := BatchBuild(dst, frames)
	if n == 0 {
		t.Fatal("пачка не собралась")
	}
	if FrameKind(dst[:n]) != KindCtl {
		t.Error("контейнер обязан опознаваться как служебный кадр")
	}
	var got [][]byte
	if !BatchIter(dst[:n], func(f []byte) { got = append(got, append([]byte(nil), f...)) }) {
		t.Fatal("своя же пачка не разобралась")
	}
	if len(got) != len(frames) {
		t.Fatalf("кадров вышло %d, а клали %d", len(got), len(frames))
	}
	for i := range frames {
		if !bytes.Equal(got[i], frames[i]) {
			t.Errorf("кадр %d испортился", i)
		}
	}
	// Накладные расходы пачки обязаны быть меньше, чем у тех же кадров поодиночке: ради этого
	// она и заведена, и если однажды станет наоборот — тест скажет.
	alone := 0
	for _, f := range frames {
		alone += Overhead + len(f)
	}
	batched := HdrRoom + n + Tag + (len(frames)-1)*0 // одна запись, сегментов может быть больше
	segs := (n + Tag + MTUDefault - 1) / MTUDefault
	batched = segs*(IPHdr+TCPHdr) + RecHdr + Tag + n
	if batched >= alone {
		t.Errorf("пачка (%d байт) не дешевле одиночных (%d)", batched, alone)
	}

	// Один кадр в контейнер не кладётся: одиночная запись дешевле на байт.
	if BatchBuild(dst, frames[:1]) != 0 {
		t.Error("один кадр упакован в контейнер")
	}
	// Битый контейнер обязан отвергаться ЦЕЛИКОМ: обработчик не должен увидеть НИ ОДНОГО
	// кадра. Портится длина ПОСЛЕДНЕГО кадра, а не первого: перед первым кадром префикса не
	// бывает по построению, поэтому порча первой длины одинаково выглядит и при разборе в два
	// прохода, и при разборе с доставкой по мере чтения — она это свойство не проверяет вовсе
	// (I-063). И обработчик здесь СЧИТАЕТ, а не пустой.
	bad := append([]byte(nil), dst[:n]...)
	lastLenAt := BatchHdr + 2 + len(frames[0]) + 2 + len(frames[1])
	bad[lastLenAt] = 0xFF
	delivered, bytesOut := 0, 0
	count := func(f []byte) { delivered++; bytesOut += len(f) }
	if BatchIter(bad, count) {
		t.Error("контейнер с завышенной длиной последнего кадра принят")
	}
	if delivered != 0 || bytesOut != 0 {
		t.Errorf("из битого контейнера доставлено %d кадров и %d байт, а обязан ноль",
			delivered, bytesOut)
	}

	bad = append(bad[:0], dst[:n]...)
	bad[1] = 0xFF // та же порча, но на длине ПЕРВОГО кадра
	delivered, bytesOut = 0, 0
	if BatchIter(bad, count) {
		t.Error("контейнер с завышенной длиной первого кадра принят")
	}
	if delivered != 0 {
		t.Errorf("из битого контейнера доставлено %d кадров, а обязан ноль", delivered)
	}

	delivered = 0
	if BatchIter(dst[:2], count) {
		t.Error("обрезок контейнера принят")
	}
	if delivered != 0 {
		t.Errorf("из обрезка контейнера доставлено %d кадров, а обязан ноль", delivered)
	}

	// Предел на число кадров обязан действовать и на ПРИЁМЕ, а не только на сборке: контейнер
	// на 8191 байт из однобайтовых кадров дал бы 2730 вызовов обработчика, тогда как законная
	// пачка не бывает длиннее BatchFramesMax кадров ни в одной из реализаций.
	over := make([][]byte, BatchFramesMax+1)
	for i := range over {
		over[i] = []byte{byte(0x50 + i)}
	}
	nlim := BatchBuild(dst, over[:BatchFramesMax])
	if nlim == 0 {
		t.Fatal("пачка предельного размера не собралась")
	}
	delivered = 0
	if !BatchIter(dst[:nlim], count) {
		t.Error("пачка предельного размера отвергнута")
	}
	if delivered != BatchFramesMax {
		t.Errorf("из предельной пачки доставлено %d кадров, а клали %d", delivered, BatchFramesMax)
	}
	nover := BatchBuild(dst, over)
	if nover == 0 {
		t.Fatal("контейнер с лишним кадром не собрался")
	}
	delivered = 0
	if BatchIter(dst[:nover], count) {
		t.Errorf("контейнер из %d кадров принят при пределе %d", len(over), BatchFramesMax)
	}
	if delivered != 0 {
		t.Errorf("из переполненного контейнера доставлено %d кадров, а обязан ноль", delivered)
	}
}

func TestОбратнаяСвязьПоСборке(t *testing.T) {
	pt := make([]byte, 8)
	if LossBuild(pt, 7) != 3 {
		t.Fatal("сообщение о потерях обязано быть тремя байтами")
	}
	if LossValue(pt[:3]) != 7 {
		t.Error("значение не читается обратно")
	}
	if LossValue([]byte{CtlProbe, 0, 7}) != -1 {
		t.Error("проба принята за сообщение о потерях")
	}
}

func TestСборкаРазрезаннойЗаписи(t *testing.T) {
	// Запись на 3000 байт, разрезанная на три сегмента: собраться обязана, смещение для nonce —
	// от ПЕРВОГО сегмента.
	const isn = 1000
	body := bytes.Repeat([]byte{0xAB}, 3000)
	rec := make([]byte, RecHdr+len(body))
	if err := RecBuild(rec, len(body)); err != nil {
		t.Fatal(err)
	}
	copy(rec[RecHdr:], body)

	var r Reasm
	parts := [][]byte{rec[:1400], rec[1400:2800], rec[2800:]}
	seq := uint32(isn + 1)
	var out []byte
	var rel uint32
	for i, p := range parts {
		b, hdr, rl, ok := r.Feed(seq, isn, p)
		if ok && len(hdr) != RecHdr {
			t.Fatalf("заголовок записи отдан длиной %d", len(hdr))
		}
		if ok {
			if i != len(parts)-1 {
				t.Fatalf("запись собралась на части %d раньше времени", i)
			}
			out, rel = b, rl
		}
		seq += uint32(len(p))
	}
	if out == nil {
		t.Fatal("запись не собралась")
	}
	if rel != 1 {
		t.Errorf("смещение для nonce = %d, а обязано быть от первого сегмента (1)", rel)
	}
	if !bytes.Equal(out, body) {
		t.Error("собранная запись не совпала с исходной")
	}

	// Пропавший средний сегмент: запись обязана быть выброшена, а не склеена из чужих байтов.
	r = Reasm{}
	r.Feed(1, 0, rec[:1400])
	if _, _, _, ok := r.Feed(1400+1000, 0, rec[2800:]); ok {
		t.Error("собралась запись из несмежных сегментов")
	}
	if r.Dropped == 0 {
		t.Error("выброшенная сборка не посчитана — обратной связи неоткуда будет взяться")
	}

	// Целая запись в одном сегменте по-прежнему разбирается сразу.
	r = Reasm{}
	one := make([]byte, RecHdr+Tag+10)
	_ = RecBuild(one, Tag+10)
	if _, _, _, ok := r.Feed(5, 0, one); !ok {
		t.Error("целая запись в одном сегменте не разобралась")
	}

	// Заявленная длина проверяется по пределу ФОРМАТА (MaxRecord), а не по пределу ПОЛЯ
	// (0xFFFF). Иначе первый же сегмент с завышенной длиной заставляет держать буфер сборки
	// до 64 КиБ на сессию, хотя записи длиннее MaxRecord мы не отправляем никогда, а тег
	// такую подделку всё равно не пропустит — только позже. В Stream.ReadRecord и в реализации
	// на C предел ровно такой.
	r = Reasm{}
	huge := make([]byte, RecMin+64)
	huge[0], huge[1], huge[2] = recType, recV0, recV1
	huge[3], huge[4] = byte((MaxRecord+1)>>8), byte((MaxRecord+1)&0xFF)
	if _, _, _, ok := r.Feed(9, 0, huge); ok {
		t.Error("запись с заявленной длиной больше MaxRecord принята")
	}
	if r.active {
		t.Errorf("сборка начата по заявленной длине %d, хотя предел формата %d",
			MaxRecord+1, MaxRecord)
	}
}

// Записи по настоящему потоку: смещения обеих сторон обязаны совпадать, иначе не расшифруется
// первый же пакет данных. Проверяется на «трубе» без всякой сети.
type pipe struct {
	buf []byte
}

func (p *pipe) Write(b []byte) (int, error) { p.buf = append(p.buf, b...); return len(b), nil }
func (p *pipe) Read(b []byte) (int, error) {
	if len(p.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func TestПотокЗаписей(t *testing.T) {
	p := &pipe{}
	tx := NewStream(p)
	rx := NewStream(p)

	// Рукопожатие двигает смещение так же, как данные: иначе стороны разойдутся ровно на его длину.
	hello := bytes.Repeat([]byte{0x16}, 1759)
	if err := tx.WriteRaw(hello); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(hello))
	if _, err := io.ReadFull(readerOf(rx), got); err != nil {
		t.Fatal(err)
	}
	if tx.TxNext() != 1+uint64(len(hello)) {
		t.Errorf("смещение отправителя после рукопожатия = %d", tx.TxNext())
	}

	// Три записи разной длины: смещение каждой обязано совпасть у обеих сторон.
	for i, plen := range []int{Tag, Tag + 100, Tag + MaxRecord/2} {
		row := make([]byte, HdrRoom+MaxRecord+Tag)
		rec := row[HdrRoom-RecHdr : HdrRoom]
		if err := RecBuild(rec, plen); err != nil {
			t.Fatal(err)
		}
		for k := 0; k < plen; k++ {
			row[HdrRoom+k] = byte(i*7 + k)
		}
		var sealedWith uint64
		want := tx.TxNext()
		err := tx.WriteRecord(row, RecHdr+plen, func(rel uint64) error {
			sealedWith = rel
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if sealedWith != want {
			t.Errorf("запись %d зашифрована смещением %d, а ушла с %d", i, sealedWith, want)
		}
		body, hdr, rel, err := rx.ReadRecord()
		if err != nil {
			t.Fatalf("запись %d не прочиталась: %v", i, err)
		}
		if rel != want {
			t.Errorf("запись %d прочитана со смещением %d, а отправлена с %d", i, rel, want)
		}
		if len(body) != plen || len(hdr) != RecHdr {
			t.Errorf("запись %d: длины %d и %d", i, len(body), len(hdr))
		}
		if !bytes.Equal(body, row[HdrRoom:HdrRoom+plen]) {
			t.Errorf("запись %d испортилась", i)
		}
	}

	// Мусор в потоке — это конец соединения, а не «пропустим кадр»: в потоке нет способа найти
	// начало следующей записи, не доверяя длине, которой мы уже не верим.
	p.buf = append(p.buf, 0x17, 0x03, 0x04, 0x00, 0x20)
	if _, _, _, err := rx.ReadRecord(); err == nil {
		t.Error("запись с чужой версией принята")
	}
	p.buf = nil
	p.buf = append(p.buf, 0x17, 0x03, 0x03, 0xFF, 0xFF)
	if _, _, _, err := rx.ReadRecord(); err == nil {
		t.Error("запись длиннее предела принята")
	}
}

// readerOf нужен, чтобы прочитать сырые байты рукопожатия и учесть их в смещении.
func readerOf(s *Stream) io.Reader { return readerFunc(s.ReadRaw) }

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) { return f(b) }

// Предел пачки и предел записи обязаны считаться ОДНИМ числом.
//
// Ограничитель на сборке мерит ОТКРЫТЫЙ текст, а приёмник (Reasm.Feed, Stream.ReadRecord и
// xs_reasm_feed в реализации на C) проверяет длину ТЕЛА, то есть открытого текста ВМЕСТЕ с тегом.
// Разница в Tag байт — не запас: пачка, которую ограничитель пропустил вплотную к пределу, уезжает
// записью длиннее предела, и собственный приёмник её отвергает. В поддельном TCP это молчаливая
// потеря пакета, а в потоке — ОБРЫВ СОЕДИНЕНИЯ: границы следующей записи известны только из длины,
// которой мы уже не верим. Наружу это выглядит как «на скорости туннель отваливается», потому что
// вплотную к пределу пачка набивается только под нагрузкой.
func TestПределПачкиИПределЗаписи(t *testing.T) {
	mtu := MTUDefault

	// Ровно тот ограничитель, что стоит в client.streamOut, client.txLoop и hub.batchFull.
	frames := make([][]byte, 0, BatchFramesMax)
	total := BatchHdr
	add := func(n int) bool {
		if len(frames) >= BatchFramesMax {
			return false
		}
		if len(frames) > 0 && total+2+mtu > MaxPlain {
			return false
		}
		f := make([]byte, n)
		for i := range f {
			f[i] = byte(len(frames)*31 + i)
		}
		frames = append(frames, f)
		total += 2 + n
		return true
	}
	// Худший случай достижим на живом трафике: семь пакетов среднего размера и один полный. При
	// пределе на MaxRecord это давало открытый текст 8190 и тело записи 8206 против предела 8192.
	for i := 0; i < BatchFramesMax-1; i++ {
		if !add(962) {
			break
		}
	}
	add(mtu)

	pt := make([]byte, MaxRecord+Tag)
	n := BatchBuild(pt, frames)
	if n == 0 {
		t.Fatalf("BatchBuild отказался собрать пачку из %d кадров, которую пропустил ограничитель", len(frames))
	}
	if body := n + Tag; body > MaxRecord {
		t.Fatalf("тело записи %d длиннее предела %d: пачка из %d кадров собрана вплотную к MaxRecord, "+
			"а не к MaxPlain", body, MaxRecord, len(frames))
	}

	// Та же запись обязана пройти через поток целиком: это и есть проверка, что предел один.
	p := &pipe{}
	tx, rx := NewStream(p), NewStream(p)
	row := make([]byte, HdrRoom+MaxRecord+Tag)
	copy(row[HdrRoom:], pt[:n])
	rec := row[HdrRoom-RecHdr : HdrRoom]
	if err := RecBuild(rec, n+Tag); err != nil {
		t.Fatalf("RecBuild отверг тело %d: %v", n+Tag, err)
	}
	if err := tx.WriteRecord(row, RecHdr+n+Tag, nil); err != nil {
		t.Fatal(err)
	}
	body, _, _, err := rx.ReadRecord()
	if err != nil {
		t.Fatalf("собственный приёмник отверг нашу же запись: %v", err)
	}
	if len(body) != n+Tag {
		t.Fatalf("прочитано тело %d, отправлено %d", len(body), n+Tag)
	}

	// И сам сборщик обязан отказывать по пределу открытого текста, а не по пределу записи: иначе
	// ограничитель у вызывающего остаётся единственной защитой.
	big := [][]byte{make([]byte, MaxPlain-BatchHdr-2), make([]byte, 1)}
	if BatchBuild(make([]byte, MaxRecord+Tag), big) != 0 {
		t.Error("BatchBuild собрал пачку длиннее MaxPlain")
	}

	// RecBuild — последний рубеж: он обязан мерить предел ФОРМАТА, а не предел ПОЛЯ. Пока он
	// пускал всё до 0xFFFF, переполнение доезжало до провода и обрывало соединение у получателя.
	if err := RecBuild(make([]byte, RecHdr), MaxRecord+1); err == nil {
		t.Error("RecBuild принял тело длиннее MaxRecord")
	}
}
