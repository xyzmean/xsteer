package noise

import (
	"bytes"
	"testing"
)

// keysPair — два направления с общим корнем, как их отдаёт рукопожатие.
func keysPair(t *testing.T) (*Keys, *Keys) {
	t.Helper()
	var key [32]byte
	var iv [12]byte
	var root [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	for i := range iv {
		iv[i] = byte(i + 100)
	}
	for i := range root {
		root[i] = byte(i + 200)
	}
	a, err := newKeys(AEADAES128, key[:], iv[:])
	if err != nil {
		t.Fatal(err)
	}
	b, err := newKeys(AEADAES128, key[:], iv[:])
	if err != nil {
		t.Fatal(err)
	}
	a.root, b.root = root, root
	return a, b
}

func sealOpen(t *testing.T, tx, rx *Keys, seq uint64, msg string) error {
	t.Helper()
	buf := make([]byte, len(msg), len(msg)+16)
	copy(buf, msg)
	aad := []byte{0x17, 0x03, 0x03, 0x00, byte(len(msg) + 16)}
	ct, err := tx.Seal(buf, len(msg), aad, seq)
	if err != nil {
		return err
	}
	got := make([]byte, len(ct))
	copy(got, ct)
	pt, err := rx.Open(got, aad, seq)
	if err != nil {
		return err
	}
	if !bytes.Equal(pt, []byte(msg)) {
		t.Fatalf("расшифровалось не то: %q вместо %q", pt, msg)
	}
	return nil
}

// Смена эпох идёт молча и обе стороны приходят к одному и тому же ключу, потому что номер эпохи
// каждая считает из смещения сама.
func TestEpochRotatesInStep(t *testing.T) {
	tx, rx := keysPair(t)
	tx.EnableEpochs()
	rx.EnableEpochs()

	// Первая эпоха.
	if err := sealOpen(t, tx, rx, 1, "первая эпоха"); err != nil {
		t.Fatalf("эпоха 0: %v", err)
	}
	if tx.EpochNow() != 0 || rx.EpochNow() != 0 {
		t.Fatalf("эпохи разошлись в начале: tx=%d rx=%d", tx.EpochNow(), rx.EpochNow())
	}

	// Смещение за границей эпохи: обе стороны обязаны перейти к следующей сами.
	if err := sealOpen(t, tx, rx, EpochBytes+7, "вторая эпоха"); err != nil {
		t.Fatalf("эпоха 1: %v", err)
	}
	if tx.EpochNow() != 1 || rx.EpochNow() != 1 {
		t.Fatalf("после границы эпохи tx=%d rx=%d, ожидалось 1", tx.EpochNow(), rx.EpochNow())
	}

	// Ещё десять границ: номер растёт ровно, ключи сходятся.
	for i := uint64(2); i < 12; i++ {
		if err := sealOpen(t, tx, rx, i*EpochBytes+3, "эпоха"); err != nil {
			t.Fatalf("эпоха %d: %v", i, err)
		}
		if tx.EpochNow() != i || rx.EpochNow() != i {
			t.Fatalf("эпоха %d: tx=%d rx=%d", i, tx.EpochNow(), rx.EpochNow())
		}
	}
}

// Ключ прошлой эпохи после двух шагов вперёд БОЛЬШЕ НЕ РАБОТАЕТ — это и есть прямая секретность:
// вскрытая память не выдаёт того, что было раньше.
func TestEpochOldKeysGone(t *testing.T) {
	tx, rx := keysPair(t)
	tx.EnableEpochs()
	rx.EnableEpochs()

	// Записываем «перехваченную» запись эпохи 0.
	msg := "старая запись"
	buf := make([]byte, len(msg), len(msg)+16)
	copy(buf, msg)
	aad := []byte{0x17, 0x03, 0x03, 0x00, byte(len(msg) + 16)}
	ct, err := tx.Seal(buf, len(msg), aad, 5)
	if err != nil {
		t.Fatal(err)
	}
	old := append([]byte(nil), ct...)

	// Уходим на две эпохи вперёд.
	if err := sealOpen(t, tx, rx, 2*EpochBytes+1, "новая"); err != nil {
		t.Fatal(err)
	}

	// Та же запись с тем же смещением уже не расшифровывается: ключи эпохи 0 стёрты.
	again := append([]byte(nil), old...)
	if _, err := rx.Open(again, aad, 5); err == nil {
		t.Fatal("запись стёртой эпохи расшифровалась — прямой секретности нет")
	}
}

// Запись, застрявшая на самой границе, не должна стоить обрыва: одна ступень назад хранится.
func TestEpochPreviousStillOpens(t *testing.T) {
	tx, rx := keysPair(t)
	tx.EnableEpochs()
	rx.EnableEpochs()

	msg := "на границе"
	buf := make([]byte, len(msg), len(msg)+16)
	copy(buf, msg)
	aad := []byte{0x17, 0x03, 0x03, 0x00, byte(len(msg) + 16)}
	ct, err := tx.Seal(buf, len(msg), aad, EpochBytes-4)
	if err != nil {
		t.Fatal(err)
	}
	late := append([]byte(nil), ct...)

	// Получатель успел уйти в следующую эпоху на другой записи.
	if err := sealOpen(t, tx, rx, EpochBytes+1, "следующая"); err != nil {
		t.Fatal(err)
	}
	if rx.EpochNow() != 1 {
		t.Fatalf("получатель в эпохе %d", rx.EpochNow())
	}
	// Опоздавшая запись прошлой эпохи всё ещё читается.
	if _, err := rx.Open(late, aad, EpochBytes-4); err != nil {
		t.Fatalf("запись прошлой эпохи не прочиталась: %v", err)
	}
}

// Ратчет НЕ МЕНЯЕТ на проводе ничего: длина шифротекста та же, что без эпох, и запись, снятая с
// провода, отличается только ключом. Это и есть требование «не выглядеть иначе, чем xhttp».
func TestEpochNoWireChange(t *testing.T) {
	plain, _ := keysPair(t)
	withEp, _ := keysPair(t)
	withEp.EnableEpochs()

	msg := bytes.Repeat([]byte("x"), 1200)
	aad := []byte{0x17, 0x03, 0x03, 0x04, 0xc4}

	mk := func(k *Keys, seq uint64) int {
		buf := make([]byte, len(msg), len(msg)+16)
		copy(buf, msg)
		ct, err := k.Seal(buf, len(msg), aad, seq)
		if err != nil {
			t.Fatal(err)
		}
		return len(ct)
	}
	// И в первой эпохе, и после десятка смен длина записи одна и та же.
	if a, b := mk(plain, 1), mk(withEp, 1); a != b {
		t.Fatalf("длина записи разошлась в эпохе 0: без эпох %d, с эпохами %d", a, b)
	}
	if a, b := mk(plain, 10*EpochBytes+1), mk(withEp, 10*EpochBytes+1); a != b {
		t.Fatalf("длина записи разошлась после смен: без эпох %d, с эпохами %d", a, b)
	}
	if withEp.EpochNow() != 10 {
		t.Fatalf("эпоха не сменилась: %d", withEp.EpochNow())
	}
}

// Выключенные эпохи означают ПРЕЖНЕЕ поведение байт в байт: это условие совместимости с
// поддельным TCP и с реализацией на C, которые про эпохи не знают.
func TestEpochOffIsUnchanged(t *testing.T) {
	a, b := keysPair(t)
	msg := "поддельный TCP"
	buf := make([]byte, len(msg), len(msg)+16)
	copy(buf, msg)
	aad := []byte{0x17, 0x03, 0x03, 0x00, byte(len(msg) + 16)}
	ct, err := a.Seal(buf, len(msg), aad, 3*EpochBytes+9) // смещение далеко за границей эпохи
	if err != nil {
		t.Fatal(err)
	}
	got := append([]byte(nil), ct...)
	if _, err := b.Open(got, aad, 3*EpochBytes+9); err != nil {
		t.Fatalf("без эпох запись обязана читаться прежним ключом: %v", err)
	}
	if a.EpochNow() != 0 || b.EpochNow() != 0 {
		t.Fatalf("эпохи двинулись при выключенном ратчете: %d/%d", a.EpochNow(), b.EpochNow())
	}
}
