package wire

import (
	"bytes"
	"testing"
)

// Буферизованное чтение НЕ должно терять байты, приехавшие вплотную за рукопожатием.
//
// Это главный риск оптимизации: буфер чтения жадный — первый же ReadFull наполняет его целиком, и
// если следом за «рукопожатием» в том же куске приехала запись данных, она уже в буфере. Читай мы
// мимо буфера (прямо из сокета), она бы пропала, и первая запись не расшифровалась бы. Тест
// закрепляет, что все чтения идут через один буфер и смещения при этом считаются верно.
func TestStreamBufferedReadAhead(t *testing.T) {
	prefix := []byte("HELLO12345") // 10 байт «рукопожатия»
	body := make([]byte, 20)       // тело записи (>= Tag)
	for i := range body {
		body[i] = byte(i + 1)
	}
	rec := make([]byte, RecHdr+len(body))
	if err := RecBuild(rec[:RecHdr], len(body)); err != nil {
		t.Fatal(err)
	}
	copy(rec[RecHdr:], body)

	// Всё в одном буфере: bufio затянет prefix и rec одним чтением.
	var buf bytes.Buffer
	buf.Write(prefix)
	buf.Write(rec)

	s := NewStream(&buf)

	got := make([]byte, len(prefix))
	if err := s.ReadFull(got); err != nil {
		t.Fatalf("ReadFull рукопожатия: %v", err)
	}
	if !bytes.Equal(got, prefix) {
		t.Fatalf("рукопожатие прочиталось как %q, ждали %q", got, prefix)
	}
	if s.rxOff != 1+uint64(len(prefix)) {
		t.Fatalf("смещение после рукопожатия %d, ждали %d", s.rxOff, 1+len(prefix))
	}

	gotBody, hdr, rel, err := s.ReadRecord()
	if err != nil {
		t.Fatalf("ReadRecord после рукопожатия: %v", err)
	}
	if rel != 1+uint64(len(prefix)) {
		t.Fatalf("смещение записи %d, ждали %d", rel, 1+len(prefix))
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("тело записи не совпало: %v", gotBody)
	}
	if hdr[0] != recType {
		t.Fatalf("заголовок записи не тот: %x", hdr)
	}
	if s.rxOff != 1+uint64(len(prefix)+RecHdr+len(body)) {
		t.Fatalf("смещение после записи %d, ждали %d", s.rxOff, 1+len(prefix)+RecHdr+len(body))
	}
}

// Смещение в потоке — это nonce, и оно ОБЯЗАНО не заворачиваться на четвёртом гигабайте.
//
// Проверка стоит здесь потому, что цена ошибки максимальная: повтор nonce с тем же ключом — это не
// ослабление AEAD, а его полная потеря. Раньше счётчики были 32-битными, и от заворота спасал ретайр
// по объёму — то есть разрыв живого соединения каждый гигабайт. Тест закрепляет свойство, ради
// которого от разрыва удалось отказаться.
func TestStreamOffsetDoesNotWrap(t *testing.T) {
	s := NewStream(nil)

	// Загоняем счётчик почти к границе 32 бит, как это сделал бы настоящий обмен.
	const nearWrap = uint64(1)<<32 - 16
	s.txOff = nearWrap
	s.rxOff = nearWrap

	// Шаг за границу: у 32-битного счётчика здесь начались бы значения с начала.
	s.txOff += 64
	s.rxOff += 64

	if s.TxNext() <= nearWrap {
		t.Fatalf("смещение отправителя завернулось: было %d, стало %d", nearWrap, s.TxNext())
	}
	if s.txOff != nearWrap+64 || s.rxOff != nearWrap+64 {
		t.Fatalf("смещения посчитались неверно: tx=%d rx=%d, ожидалось %d", s.txOff, s.rxOff, nearWrap+64)
	}
	// И ещё терабайт сверху: значения по-прежнему растут монотонно.
	s.txOff += 1 << 40
	if s.txOff <= nearWrap+64 {
		t.Fatalf("смещение перестало расти после терабайта: %d", s.txOff)
	}
}
