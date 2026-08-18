// Проверки облика и разбора. Случаи те же, что в tests/chellomatch.c и tests/hellofreeze.c
// движка на C: Hello — единственное место протокола, которое видно снаружи целиком, поэтому
// проверяется не «собралось», а состав, размеры и то, что битое отвергается, не читая за буфером.
package chello

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"testing"
)

// детерминированный источник: без него собранный Hello невозможно сравнить с эталоном, а без
// такого сравнения любая правка облика проходит незамеченной.
type seeded struct{ r *rand.Rand }

func (s seeded) Read(p []byte) (int, error) { return s.r.Read(p) }

func carrier(pub byte) *Carrier {
	var c Carrier
	for i := range c.Pub {
		c.Pub[i] = pub
	}
	c.FillECH = func(pay []byte) error {
		// Носитель занимает первые 64 байта, остальное — шум. Здесь важно только то, что
		// сборщик отдаёт ровно ECHPayload байт и на то же место, куда потом смотрит разбор.
		for i := 0; i < 64 && i < len(pay); i++ {
			pay[i] = byte(0xC0 + i%16)
		}
		return nil
	}
	c.FillSID = func(sid, hs []byte) error {
		// Подпись здесь не настоящая, но зависит от ВСЕХ подписываемых байтов — как и настоящая.
		// Так тест поймает подмену подписываемой части: если бы сборщик отдал носителю память,
		// в которую сам же пишет, эта сумма перестала бы сходиться с посчитанной у второй
		// стороны.
		h := sha256.Sum256(hs)
		copy(sid, h[:32])
		return nil
	}
	return &c
}

func TestСоставИРазмеры(t *testing.T) {
	car := carrier(0x11)
	rec, err := Build("www.microsoft.com", true, car, seeded{rand.New(rand.NewSource(42))})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := Parse(rec)
	if err != nil {
		t.Fatalf("свой же Hello не разобрался: %v", err)
	}
	if ref.SNI != "www.microsoft.com" {
		t.Errorf("SNI = %q", ref.SNI)
	}
	if ref.Suite != 0x1301 {
		t.Errorf("при аппаратном AES первым набором TLS 1.3 обязан быть 0x1301, а вышел %04x", ref.Suite)
	}
	if ref.ECHLen != ECHPayload {
		t.Errorf("набивка ECH %d байт, а у Chrome ровно %d", ref.ECHLen, ECHPayload)
	}
	if !bytes.Equal(rec[ref.KSOff:ref.KSOff+32], car.Pub[:]) {
		t.Error("в key_share уехал не наш эфемерный ключ")
	}
	// Носитель заполнил начало набивки — разбор обязан указывать ровно на то же место.
	if rec[ref.ECHOff] != 0xC0 {
		t.Error("смещение набивки ECH в разборе не совпало со сборкой")
	}
	// Подпись обязана быть посчитана по подписываемым байтам с ОБНУЛЁННЫМ session_id: ровно так
	// её восстановит вторая сторона.
	hs := append([]byte(nil), rec[ref.HSOff:ref.HSOff+ref.HSLen]...)
	for i := 0; i < 32; i++ {
		hs[ref.SIDOff-ref.HSOff+i] = 0
	}
	want := sha256.Sum256(hs)
	if !bytes.Equal(rec[ref.SIDOff:ref.SIDOff+32], want[:]) {
		t.Fatal("подписанные байты не восстанавливаются обнулением session_id — вторая сторона " +
			"не сойдётся тегом при полностью верной криптографии")
	}

	// Без аппаратного AES порядок наборов меняется, и вместе с ним — согласованный шифр. Это не
	// косметика: на слабом процессоре разница между шифрами измеряется разами.
	rec2, err := Build("example.org", false, carrier(0x22), seeded{rand.New(rand.NewSource(42))})
	if err != nil {
		t.Fatal(err)
	}
	ref2, err := Parse(rec2)
	if err != nil {
		t.Fatal(err)
	}
	if ref2.Suite != 0x1303 {
		t.Errorf("без AES первым обязан быть ChaCha20 (0x1303), а вышел %04x", ref2.Suite)
	}

	// Hello обязан влезать в один сегмент вместе с заголовками: пересборки потока в транспорте
	// нет вовсе, а у рукопожатия она есть только на приёме ответа.
	if len(rec) > 1400 {
		t.Errorf("Hello вышел %d байт — он обязан влезать в сегмент", len(rec))
	}
}

func TestОбликПовторяетБраузер(t *testing.T) {
	rec, err := Build("www.microsoft.com", true, carrier(0x33), seeded{rand.New(rand.NewSource(7))})
	if err != nil {
		t.Fatal(err)
	}
	// Заголовок записи: 0x16 и версия 0x0301 — так делают браузеры и openssl. Правка на 0x0303
	// «по логике» здесь уже была сделана однажды и откачена.
	if rec[0] != 0x16 || rec[1] != 0x03 || rec[2] != 0x01 {
		t.Errorf("заголовок записи % x", rec[:3])
	}
	ref, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	types, first, last := extTypes(t, rec, ref)
	// Первое и последнее расширение — GREASE и на месте: перемешивается только середина, ровно
	// как у Chrome 110+.
	if !IsGrease(first) || !IsGrease(last) {
		t.Errorf("края расширений обязаны быть GREASE, а вышли %04x и %04x", first, last)
	}
	if first == last {
		t.Error("два GREASE-расширения с одним типом — это расширение, повторённое дважды, чего в TLS быть не может")
	}
	must := []uint16{0x0000, 0x0010, 0x001B, ExtECH, 0x44CD, 0xFF01, 0x0017, 0x0023, 0x0005,
		0x002B, 0x0012, 0x000D, 0x0033, 0x000A, 0x002D, 0x000B}
	for _, m := range must {
		if !contains(types, m) {
			t.Errorf("нет расширения %04x — Hello отличим по одному отсутствующему расширению", m)
		}
	}
	if len(types) != len(must)+2 {
		t.Errorf("расширений %d, а ждали %d: лишнее в этом списке так же заметно, как недостающее",
			len(types), len(must)+2)
	}
	seen := map[uint16]bool{}
	for _, tp := range types {
		if seen[tp] {
			t.Errorf("расширение %04x повторено", tp)
		}
		seen[tp] = true
	}

	// Порядок середины обязан МЕНЯТЬСЯ: постоянный сам был бы отпечатком.
	same := 0
	base, _, _ := extTypes(t, rec, ref)
	for i := 0; i < 20; i++ {
		r2, err := Build("www.microsoft.com", true, carrier(0x44), nil)
		if err != nil {
			t.Fatal(err)
		}
		f2, err := Parse(r2)
		if err != nil {
			t.Fatal(err)
		}
		o2, _, _ := extTypes(t, r2, f2)
		if equalTypes(base, o2) {
			same++
		}
	}
	if same > 2 {
		t.Errorf("порядок расширений повторился %d раз из 20 — перемешивание не работает", same)
	}
}

func extTypes(t *testing.T, rec []byte, ref *Ref) (all []uint16, first, last uint16) {
	t.Helper()
	// Пройти список расширений заново, снаружи разбора: так проверяется то, что реально уехало,
	// а не то, что разбор счёл важным.
	i := ref.HSOff + 4 + 2 + 32 + 1 + 32
	sl := int(rec[i])<<8 | int(rec[i+1])
	i += 2 + sl
	i += 1 + int(rec[i])
	el := int(rec[i])<<8 | int(rec[i+1])
	i += 2
	end := i + el
	for i < end {
		typ := uint16(rec[i])<<8 | uint16(rec[i+1])
		ln := int(rec[i+2])<<8 | int(rec[i+3])
		all = append(all, typ)
		i += 4 + ln
	}
	if len(all) == 0 {
		t.Fatal("расширений нет вовсе")
	}
	return all, all[0], all[len(all)-1]
}

func contains(s []uint16, v uint16) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func equalTypes(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestGREASE(t *testing.T) {
	for n := 0; n < 16; n++ {
		v := uint16(0x0A0A + n*0x1010)
		if !IsGrease(v) {
			t.Errorf("%04x обязано опознаваться как GREASE", v)
		}
	}
	for _, v := range []uint16{0x1301, 0x1303, 0x0A0B, 0x0B0A, 0x0A1A} {
		if IsGrease(v) {
			t.Errorf("%04x опознано как GREASE, а это настоящее значение", v)
		}
	}
}

func TestБитыеHelloОтвергаются(t *testing.T) {
	rec, err := Build("www.microsoft.com", true, carrier(0x55), seeded{rand.New(rand.NewSource(9))})
	if err != nil {
		t.Fatal(err)
	}
	// Обрезки любой длины: ни паники, ни принятого куска.
	for n := 0; n < len(rec); n++ {
		if _, err := Parse(rec[:n]); err == nil {
			t.Fatalf("обрезок %d байт принят за целый Hello", n)
		}
	}
	// Порча каждого байта длины: разбор обязан отвергать, а не читать за буфером. Проверяем все
	// байты — а не выборочно, — потому что цена ошибки здесь читается как чтение чужой памяти.
	for i := 0; i < len(rec); i++ {
		for _, delta := range []byte{1, 0x80, 0xFF} {
			bad := append([]byte(nil), rec...)
			bad[i] ^= delta
			_, _ = Parse(bad) // важно только то, что не было паники
		}
	}
	tail := append(append([]byte(nil), rec...), 0)
	if _, err := Parse(tail); err == nil {
		t.Error("запись с лишним байтом на конце принята — за концом можно было бы спрятать байты")
	}
	notHello := append([]byte(nil), rec...)
	notHello[5] = 0x02 // ServerHello вместо ClientHello
	if _, err := Parse(notHello); err == nil {
		t.Error("ServerHello принят за ClientHello")
	}
}

// Замороженный отпечаток: не байты (они разные на каждое соединение из-за GREASE и
// перемешивания), а то, что от соединения к соединению меняться НЕ должно — длина Hello при
// заданном SNI и набор длин расширений. Если правка облика меняет это, тест обязан сказать об
// этом до того, как правка уедет в релиз.
func TestЗамороженныйСлепок(t *testing.T) {
	rec, err := Build("www.microsoft.com", true, carrier(0x66), seeded{rand.New(rand.NewSource(1))})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := Parse(rec)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.New()
	lens := map[uint16]int{}
	i := ref.HSOff + 4 + 2 + 32 + 1 + 32
	sl := int(rec[i])<<8 | int(rec[i+1])
	i += 2 + sl
	i += 1 + int(rec[i])
	el := int(rec[i])<<8 | int(rec[i+1])
	i += 2
	for end := i + el; i < end; {
		typ := uint16(rec[i])<<8 | uint16(rec[i+1])
		ln := int(rec[i+2])<<8 | int(rec[i+3])
		if !IsGrease(typ) {
			lens[typ] = ln
		}
		i += 4 + ln
	}
	// Сортированная свёртка «тип:длина» — то, что видит наблюдатель и что обязано совпадать с
	// браузером.
	for _, tp := range []uint16{0x0000, 0x0005, 0x000A, 0x000B, 0x000D, 0x0010, 0x0012, 0x0017,
		0x001B, 0x0023, 0x002B, 0x002D, 0x0033, 0x44CD, ExtECH} {
		ln, ok := lens[tp]
		if !ok {
			t.Fatalf("расширения %04x нет", tp)
		}
		sum.Write([]byte{byte(tp >> 8), byte(tp), byte(ln >> 8), byte(ln)})
	}
	got := hex.EncodeToString(sum.Sum(nil)[:8])
	const want = "3c85f68474fb23dc"
	if got != want {
		t.Errorf("слепок длин расширений изменился: %s (был %s).\n"+
			"Если правка облика сделана НАРОЧНО — сверьте Hello с перехватом настоящего Chrome и\n"+
			"обновите слепок вместе с этим объяснением. Если нет — облик уехал случайно.", got, want)
	}
	// Длина Hello — 520 байт плюс длина SNI, и это число сверено с движком на C: его
	// замороженный эталон (tests/chello-frozen.h) при SNI из 15 символов занимает ровно 535
	// байт, наборы шифров в нём те же шестнадцать, а расширений те же восемнадцать с теми же
	// длинами. То есть облик двух реализаций совпадает не «по замыслу», а по числам.
	if want := 520 + len("www.microsoft.com"); len(rec) != want {
		t.Errorf("длина Hello %d, а обязана быть %d — как у эталона движка на C", len(rec), want)
	}
}
