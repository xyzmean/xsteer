//go:build linux

package noise

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ПОЧЕМУ ЭТИ ДВА ТЕСТА ВЫГЛЯДЯТ ОКОЛЬНО.
//
// Ядерный шифр (AF_ALG, тип «aead») проверить напрямую можно только там, где загружен фронтенд
// algif_aead. А он загружен далеко не всегда и не по недосмотру: на машине сборки этого проекта он
// выключен явным `install algif_aead /bin/false` из-за CVE-2026-31431, а в OpenWrt для него нужен
// отдельный пакет kmod-crypto-user. То есть «запустить и посмотреть» — не всегда доступная роскошь,
// а самая рискованная часть кода (ручная сборка управляющих сообщений: выравнивание заголовков,
// порядок байт полей ядра, упаковка af_alg_iv) ошибается молча и проявляется несошедшимся тегом.
//
// Поэтому проверяется она с двух сторон, и ни одна не требует algif_aead:
//
//  1. РАЗБОРОМ СВОЕГО ЖЕ БУФЕРА. Собранные нами управляющие сообщения разбираются штатным
//     ParseSocketControlMessage — тем же кодом, каким их читает ядро по смыслу. Это ловит
//     выравнивание, длины и порядок, то есть всё, что можно перепутать в раскладке.
//  2. ЖИВЫМ ЯДРОМ НА ДРУГОМ ФРОНТЕНДЕ. algif_skcipher принимает ТЕ ЖЕ ALG_SET_OP и ALG_SET_IV тем
//     же механизмом, и он обычно доступен (под CVE он не попал). Значит на нём можно прогнать
//     настоящий вызов и сверить результат с эталоном — и если плумбинг неверен, это видно сразу.
//
// Сам шифр при этом сверяется с эталоном ЕЩЁ И В РАБОТЕ, на той машине, где выбирается:
// algSelfTest вызывается до того, как через движок пойдёт трафик (см. KernelUsable).

// TestУправляющиеСообщенияAFALGРазбираются — раскладка cmsg верна.
func TestУправляющиеСообщенияAFALGРазбираются(t *testing.T) {
	iv := make([]byte, 12)
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	ctrl := algCtrl(unix.ALG_OP_ENCRYPT, iv, 5)
	msgs, err := unix.ParseSocketControlMessage(ctrl)
	if err != nil {
		t.Fatalf("свой же буфер не разобрался: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("сообщений %d, ждали 3 (op, iv, assoclen)", len(msgs))
	}
	want := []int{unix.ALG_SET_OP, unix.ALG_SET_IV, unix.ALG_SET_AEAD_ASSOCLEN}
	for i, m := range msgs {
		if m.Header.Level != unix.SOL_ALG {
			t.Errorf("сообщение %d: уровень %d, а не SOL_ALG", i, m.Header.Level)
		}
		if int(m.Header.Type) != want[i] {
			t.Errorf("сообщение %d: тип %d, а не %d", i, m.Header.Type, want[i])
		}
	}
	if got := hostU32(msgs[0].Data); got != unix.ALG_OP_ENCRYPT {
		t.Errorf("операция: %d", got)
	}
	// af_alg_iv: длина, потом сам nonce.
	if got := hostU32(msgs[1].Data[:4]); int(got) != len(iv) {
		t.Errorf("длина nonce в сообщении: %d, а не %d", got, len(iv))
	}
	if !bytes.Equal(msgs[1].Data[4:4+len(iv)], iv) {
		t.Errorf("nonce в сообщении не тот: %x", msgs[1].Data[4:])
	}
	if got := hostU32(msgs[2].Data); got != 5 {
		t.Errorf("длина AAD: %d, а не 5", got)
	}
}

func hostU32(b []byte) uint32 {
	if isLittleEndian {
		return binary.LittleEndian.Uint32(b)
	}
	return binary.BigEndian.Uint32(b)
}

// TestПлумбингAFALGНаЖивомЯдре — настоящий вызов AF_ALG сверяется с эталоном.
//
// Берётся ctr(aes): это skcipher, а не aead, поэтому фронтенд другой (algif_skcipher) и под
// CVE-2026-31431 он не попадает. Механизм передачи операции и nonce тот же самый, что у нашего
// шифра, — а значит на нём проверяется ровно то, что нельзя проверить рассуждением.
func TestПлумбингAFALGНаЖивомЯдре(t *testing.T) {
	if _, err := os.Stat("/sys/module/algif_skcipher"); err != nil {
		t.Skip("пропущено: algif_skcipher не загружен — плумбинг проверяется разбором буфера выше")
	}
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("пропущено: AF_ALG недоступен (%v)", err)
	}
	defer unix.Close(fd)
	if err := unix.Bind(fd, &unix.SockaddrALG{Type: "skcipher", Name: "ctr(aes)"}); err != nil {
		t.Skipf("пропущено: ядро не даёт ctr(aes) через AF_ALG (%v)", err)
	}
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i * 9)
	}
	if err := unix.SetsockoptString(fd, unix.SOL_ALG, unix.ALG_SET_KEY, string(key)); err != nil {
		t.Fatalf("ключ не принят: %v", err)
	}
	op, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
	if err != nil {
		// Отказ выдать рабочий дескриптор — свойство машины, а не нашего кода: привязка и ключ уже
		// приняты, а accept на AF_ALG закрывают и вендорские заплатки, и политики вроде AppArmor.
		// На машине сборки этого проекта именно так и происходит (ECONNABORTED при загруженном
		// algif_skcipher), поэтому здесь пропуск, а не провал: раскладку сообщений проверяет тест
		// выше, а сам шифр сверяется с эталоном в работе (KernelUsable → algSelfTest).
		t.Skipf("пропущено: ядро не выдало рабочий дескриптор AF_ALG (%v) — живой вызов проверить "+
			"на этой машине нечем", err)
	}
	defer unix.Close(op)

	pt := make([]byte, 1440)
	for i := range pt {
		pt[i] = byte(i * 31)
	}
	iv := make([]byte, 16)
	for i := range iv {
		iv[i] = byte(200 - i)
	}
	// Управляющие сообщения собираются НАШИМ кодом: проверяется он, а не библиотека.
	ctrl := algCtrl(unix.ALG_OP_ENCRYPT, iv, 0)
	// assoclen у skcipher не нужен, поэтому третье сообщение отрезаем: ядро отвергло бы неизвестный
	// ему тип.
	msgs, _ := unix.ParseSocketControlMessage(ctrl)
	ctrl = ctrl[:unix.CmsgSpace(len(msgs[0].Data))+unix.CmsgSpace(len(msgs[1].Data))]
	if err := sendmsgAlg(op, pt, ctrl); err != nil {
		t.Fatalf("sendmsg: %v", err)
	}
	got := make([]byte, len(pt))
	for n := 0; n < len(got); {
		k, err := unix.Read(op, got[n:])
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if k == 0 {
			t.Fatalf("ядро отдало %d байт из %d", n, len(got))
		}
		n += k
	}

	blk, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]byte, len(pt))
	cipher.NewCTR(blk, iv).XORKeyStream(want, pt)
	if !bytes.Equal(got, want) {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("ядро дало другой шифротекст, первое расхождение в байте %d — значит "+
					"управляющие сообщения собраны неверно", i)
			}
		}
	}
}

// TestЯдерныйШифрСверяетсяСЭталоном — если algif_aead всё же доступен, гоняем полную сверку.
func TestЯдерныйШифрСверяетсяСЭталоном(t *testing.T) {
	for _, kind := range []AEAD{AEADAES128, AEADChaCha} {
		if err := algProbe(kind); err != nil {
			t.Logf("пропущено (%s): %v", kind, err)
			continue
		}
		if err := algSelfTest(kind); err != nil {
			t.Errorf("%s: %v", kind, err)
		}
	}
}

var _ = unsafe.Pointer(nil)
