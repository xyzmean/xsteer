// Пакет chello — ClientHello с обликом Chrome: сборка и разбор.
//
// ЗАЧЕМ ЭТО ЗДЕСЬ. Рукопожатие xsteer целиком едет внутри ClientHello: эфемерный ключ — в
// key_share, статический ключ пира — в набивке фальшивого ECH, аутентификатор всего Hello — в
// legacy_session_id. Значит Hello обязан быть неотличим от браузерного не «примерно», а по
// составу и порядку расширений, списку шифров и значениям GREASE: любое отклонение делает нас
// нетипичным клиентом, и это само по себе признак, даже если вся криптография верна.
//
// В движке на C сборка живёт в src/ext/reality.c (там она общая с клиентом VLESS), а разбор — в
// src/ext/chello.c. Здесь они рядом, потому что VLESS в этом порте нет, и делить их было бы
// делением ради симметрии.
//
// ПОЧЕМУ СБОРКА НЕ ВЗЯТА ИЗ crypto/tls. Стандартная библиотека прислала бы свой порядок
// расширений, свой список шифров и свой набор GREASE — то есть отпечаток Go, а не Chrome. Как
// раз это и опознаётся: отпечаток Go на :443 встречается редко и означает «не браузер». Поэтому
// байты пишутся вручную, ровно как в C.
//
// ЧТО ЗДЕСЬ ГРАНИЦА ДОВЕРИЯ. Parse смотрит на байты, присланные кем угодно (у хаба — прямо из
// интернета). Поэтому: ни одного чтения за пределами буфера, все длины проверяются перед
// использованием, ни одной записи в разбираемый буфер. В Go выход за границу — паника, а не
// тихое чтение чужой памяти, но паника в потоке приёма означает упавший клиент, то есть тот же
// обрыв туннеля.
package chello

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// Группа x25519 в supported_groups и key_share; фальшивое расширение ECH, в набивке которого
// едет запечатанный статический ключ.
const (
	GroupX25519 = 0x001D
	ExtECH      = 0xFE0D
	// ECHPayload — размер набивки ECH. Ровно столько же, сколько у Chrome без настроенного ECH:
	// расширение целиком выходит 218 байт, и отличие хотя бы в одном байте делает Hello
	// отличимым по размеру одного расширения.
	ECHPayload = 176
)

// IsGrease — значение GREASE (RFC 8701): те, что браузер вставляет нарочно, чтобы посредники не
// считали неизвестное недопустимым. Пропускать их обязательно: иначе «первым набором шифров»
// окажется заведомо несуществующий, и согласование AEAD сломается на ровном месте.
func IsGrease(v uint16) bool {
	return v&0x0F0F == 0x0A0A && byte(v>>8) == byte(v)
}

// Carrier — то, что xsteer подкладывает в чужой по форме Hello.
//
// Порядок вызова важен для ОБЕИХ сторон и повторяет C: сначала FillECH (набивка входит в
// подписываемые байты), потом FillSID (подписывает весь Hello с обнулённым session_id). Тот же
// порядок повторяет хаб, разбирая полученное.
type Carrier struct {
	// Pub — готовый эфемерный публичный ключ. Приходит снаружи, потому что общий секрет с хабом
	// выводится из него ЕЩЁ ДО сборки Hello: этим секретом запечатывается статический ключ.
	Pub [32]byte
	// FillECH заполняет набивку ECH (ровно ECHPayload байт). Остаток, который вызывающий не
	// тронул, обязан быть случайным — у Chrome там ровно шум.
	FillECH func(pay []byte) error
	// FillSID заполняет 32 байта session_id. hs — сообщение рукопожатия с УЖЕ ОБНУЛЁННЫМ
	// session_id, то есть ровно те байты, которые вторая сторона сможет восстановить у себя.
	FillSID func(sid, hs []byte) error
}

// Наборы шифров Chrome, в его порядке. Сверено с перехватом браузера.
//
// 0x1302 (AES_256_GCM_SHA384) в списке есть, хотя расписание ключей у нас только на SHA-256.
// Это не оплошность: список обязан совпадать с браузерным, иначе весь смысл маскировки теряется,
// — а выбирает набор та сторона, которая отвечает, и из наших она возьмёт первый, который
// умеет. Хаб xsteer читает первый набор TLS 1.3 и отвечает 0x1301 или 0x1303.
var suitesAES = []uint16{
	0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
	0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
}

// Тот же список в порядке BoringSSL для процессора БЕЗ инструкций AES: ChaCha20 поднята выше
// AES-GCM и в 1.3, и в 1.2. Ровно это делает Chrome (EVP_has_aes_hardware в ssl_cipher.cc),
// поэтому отпечаток остаётся браузерным — меняется не состав, а порядок, и меняется он так же,
// как у настоящего Chrome на таком же процессоре.
//
// Порядок здесь несёт СОГЛАСОВАНИЕ ШИФРА, а не только облик: хаб берёт первый набор TLS 1.3 из
// нашего списка. На роутере с MIPS это была разница между 1,7 и 11,6 МБ/с; на десктопе с
// аппаратным AES выбор обратный, и потому решает именно клиент — он один знает своё железо.
var suitesChaCha = []uint16{
	0x1303, 0x1301, 0x1302, 0xCCA9, 0xCCA8, 0xC02B, 0xC02F, 0xC02C, 0xC030,
	0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
}

// signature_algorithms: восемь, в порядке Chrome.
var sigAlgs = []uint16{0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601}

var errTooBig = errors.New("chello: Hello не влез в буфер")

type buf struct{ b []byte }

func (w *buf) u8(v byte)     { w.b = append(w.b, v) }
func (w *buf) u16(v int)     { w.b = append(w.b, byte(v>>8), byte(v)) }
func (w *buf) put(d ...byte) { w.b = append(w.b, d...) }
func (w *buf) puts(s string) { w.b = append(w.b, s...) }
func (w *buf) len() int      { return len(w.b) }

type pend struct {
	typ  int
	body []byte
}

// ext собирает одно расширение: тип, длина, тело.
func ext(typ int, body []byte) pend { return pend{typ, body} }

// Build собирает ClientHello и возвращает готовую ЗАПИСЬ TLS (вместе с заголовком 0x16).
//
// aesPreferred решает порядок наборов шифров, то есть какой AEAD выберет хаб. На десктопе это
// почти всегда true (аппаратный AES есть у всякого x86-64 и arm64 последних лет), но решение
// остаётся за вызывающим: он один знает, на чём исполняется, а разница между шифрами на слабом
// процессоре — разница в разы.
//
// rnd — источник случайности; nil означает crypto/rand. Явный параметр нужен тесту: собранный
// Hello иначе невозможно сравнить с замороженным эталоном, а без такого сравнения любая правка
// облика проходит незамеченной.
func Build(sni string, aesPreferred bool, car *Carrier, rnd io.Reader) ([]byte, error) {
	if car == nil || car.FillECH == nil || car.FillSID == nil {
		return nil, errors.New("chello: без носителя собирать Hello незачем")
	}
	if sni == "" {
		sni = "www.microsoft.com"
	}
	if len(sni) > 250 {
		return nil, errTooBig
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	rb := func(n int) ([]byte, error) {
		out := make([]byte, n)
		if _, err := io.ReadFull(rnd, out); err != nil {
			return nil, fmt.Errorf("chello: нет случайности: %w", err)
		}
		return out, nil
	}

	random, err := rb(32)
	if err != nil {
		return nil, err
	}
	// Значения GREASE — свои на каждое соединение. Постоянные сами стали бы отпечатком: именно
	// непредсказуемость здесь и есть смысл GREASE. Значения — 0x0a0a + n*0x1010, то есть
	// шестнадцать вариантов от 0x0a0a до 0xfafa. Два ТИПА расширений обязаны отличаться друг от
	// друга: одинаковые дали бы расширение, повторённое дважды, чего в TLS быть не может.
	gr, err := rb(5)
	if err != nil {
		return nil, err
	}
	greaseOf := func(b byte) int { return 0x0A0A + int(b&15)*0x1010 }
	gCipher, gGroup, gVersion := greaseOf(gr[0]), greaseOf(gr[1]), greaseOf(gr[2])
	gExtA := greaseOf(gr[3])
	nb := gr[4] & 15
	if nb == gr[3]&15 {
		nb ^= 1
	}
	gExtB := greaseOf(nb)

	w := &buf{b: make([]byte, 0, 700)}
	w.u8(0x16)
	// Версия записи 0x0301 — так делает и openssl, и браузеры. Правка на 0x0303 в этом месте
	// уже однажды была сделана «по логике» и откачена: логика была ни при чём, а сравнение с
	// рабочим клиентом показало 0x0301.
	w.u16(0x0301)
	recLenAt := w.len()
	w.u16(0)

	hsAt := w.len()
	w.u8(0x01)
	hsLenAt := w.len()
	w.put(0, 0, 0) // 24-битная длина

	w.u16(0x0303) // legacy_version TLS 1.2 — так требует 1.3
	w.put(random...)
	w.u8(32)
	sidAt := w.len()
	w.put(make([]byte, 32)...) // место аутентификатора: заполняется в конце

	suites := suitesChaCha
	if aesPreferred {
		suites = suitesAES
	}
	w.u16((len(suitesAES) + 1) * 2)
	w.u16(gCipher)
	for _, s := range suites {
		w.u16(int(s))
	}
	w.put(1, 0) // compression: null

	extsLenAt := w.len()
	w.u16(0)
	extsAt := w.len()

	// Расширения складываются в таблицу и лишь потом пишутся: Chrome начиная с 110-й версии
	// ПЕРЕМЕШИВАЕТ их порядок на каждом соединении, оставляя на месте первое и последнее.
	// Фиксированный порядок сам был бы отпечатком.
	var px []pend

	px = append(px, ext(gExtA, nil)) // первым — GREASE, пустой

	{ // server_name: список(2) + тип(1) + длина(2) + имя
		s := &buf{}
		s.u16(len(sni) + 3)
		s.u8(0)
		s.u16(len(sni))
		s.puts(sni)
		px = append(px, ext(0x0000, s.b))
	}
	{ // ALPN: ВСЕГДА h2 и http/1.1, как браузер
		s := &buf{}
		s.u16(12)
		s.u8(2)
		s.puts("h2")
		s.u8(8)
		s.puts("http/1.1")
		px = append(px, ext(0x0010, s.b))
	}
	{ // compress_certificate: brotli
		s := &buf{}
		s.u8(2)
		s.u16(0x0002)
		px = append(px, ext(0x001B, s.b))
	}
	{
		// encrypted_client_hello — НАБИВКА, а не настоящий ECH.
		//
		// Chrome без конфигурации ECH посылает именно это: расширение правильной формы, набитое
		// случайными байтами. Настоящий ECH нам не нужен и не с чем согласовывать; нужна ровно
		// та же форма и тот же размер, иначе Hello отличим по одному расширению.
		//
		// Раскладка: тип(1)=0 внешний, kdf(2)=HKDF-SHA256, aead(2)=AES-128-GCM, номер
		// конфигурации(1), длина enc(2)=32 и сам enc, длина payload(2)=176 и payload. Итого
		// 1+2+2+1+2+32+2+176 = 218 байт.
		noise, err := rb(1 + 32 + ECHPayload)
		if err != nil {
			return nil, err
		}
		// Носитель заполняет ровно те байты, которые уедут полезной нагрузкой. Заполняется
		// ЗДЕСЬ, а не после сборки: набивка входит в байты, которые потом подписывает
		// session_id, и это буквально будущая нагрузка, а не смещение, посчитанное по раскладке.
		if err := car.FillECH(noise[33:]); err != nil {
			return nil, err
		}
		s := &buf{}
		s.u8(0x00)
		s.u16(0x0001)
		s.u16(0x0001)
		s.u8(noise[0])
		s.u16(32)
		s.put(noise[1:33]...)
		s.u16(ECHPayload)
		s.put(noise[33:]...)
		px = append(px, ext(ExtECH, s.b))
	}
	{ // application_settings (ALPS): список из одного "h2"
		s := &buf{}
		s.u16(3)
		s.u8(2)
		s.puts("h2")
		px = append(px, ext(0x44CD, s.b))
	}
	px = append(px, ext(0xFF01, []byte{0}))             // renegotiation_info
	px = append(px, ext(0x0017, nil))                   // extended_master_secret
	px = append(px, ext(0x0023, nil))                   // session_ticket
	px = append(px, ext(0x0005, []byte{1, 0, 0, 0, 0})) // status_request: OCSP, пустые списки
	{
		// supported_versions: GREASE, 1.3, 1.2. TLS 1.2 в списке есть потому, что он есть у
		// браузера; отвечающая сторона выберет 1.3.
		s := &buf{}
		s.u8(6)
		s.u16(gVersion)
		s.u16(0x0304)
		s.u16(0x0303)
		px = append(px, ext(0x002B, s.b))
	}
	px = append(px, ext(0x0012, nil)) // signed_certificate_timestamp
	{
		s := &buf{}
		s.u16(len(sigAlgs) * 2)
		for _, a := range sigAlgs {
			s.u16(int(a))
		}
		px = append(px, ext(0x000D, s.b))
	}
	{
		// key_share: GREASE-группа с одним нулевым байтом, затем наша половина X25519. Номер
		// GREASE-группы тот же, что в supported_groups — так делает браузер.
		s := &buf{}
		s.u16(41)
		s.u16(gGroup)
		s.u16(1)
		s.u8(0)
		s.u16(GroupX25519)
		s.u16(32)
		s.put(car.Pub[:]...)
		px = append(px, ext(0x0033, s.b))
	}
	{
		// supported_groups: GREASE, X25519, secp256r1, secp384r1 — ровно набор Chrome.
		s := &buf{}
		s.u16(8)
		s.u16(gGroup)
		s.u16(GroupX25519)
		s.u16(0x0017)
		s.u16(0x0018)
		px = append(px, ext(0x000A, s.b))
	}
	px = append(px, ext(0x002D, []byte{1, 1})) // psk_key_exchange_modes
	px = append(px, ext(0x000B, []byte{1, 0})) // ec_point_formats
	px = append(px, ext(gExtB, []byte{0}))     // последним — второй GREASE

	// Перемешиваем всё, кроме первого и последнего.
	//
	// Тасование здесь РОВНОМЕРНОЕ, в отличие от C: там индекс берётся как остаток случайного
	// байта от размера остатка, то есть с перекосом. Байтовое совпадение с C тут и не нужно —
	// порядок в любом случае свой на каждое соединение, — а перекос означал бы, что некоторые
	// перестановки встречаются заметно чаще, и по этому распределению отпечаток однажды сложат.
	if n := len(px); n > 3 {
		sh, err := rb(n)
		if err != nil {
			return nil, err
		}
		for i := n - 2; i > 1; i-- {
			j := 1 + int(sh[i])%i
			px[i], px[j] = px[j], px[i]
		}
	}
	for _, p := range px {
		w.u16(p.typ)
		w.u16(len(p.body))
		w.put(p.body...)
	}

	// Обратная засыпка длин.
	out := w.b
	extsLen := len(out) - extsAt
	out[extsLenAt], out[extsLenAt+1] = byte(extsLen>>8), byte(extsLen)
	hsLen := len(out) - hsAt - 4
	out[hsLenAt], out[hsLenAt+1], out[hsLenAt+2] = byte(hsLen>>16), byte(hsLen>>8), byte(hsLen)
	recLen := len(out) - recLenAt - 2
	out[recLenAt], out[recLenAt+1] = byte(recLen>>8), byte(recLen)

	// Аутентификатор подписывает ВЕСЬ Hello, поэтому считается последним. Носителю отдаётся
	// сообщение рукопожатия с обнулённым session_id — ровно те байты, которые вторая сторона
	// восстановит у себя, обнулив это поле в принятом Hello.
	//
	// КОПИЯ ОБЯЗАТЕЛЬНА, а не срез out[5:]. Носитель пишет 32 байта в session_id и тем же
	// вызовом считает тег по подписываемым байтам; если бы это была одна и та же память, первая
	// половина записи испортила бы то, что подписывается, и хаб не сошёлся бы тегом — при
	// полностью верной криптографии. В C копия есть по той же причине.
	hsCopy := make([]byte, len(out)-5)
	copy(hsCopy, out[5:])
	if err := car.FillSID(out[sidAt:sidAt+32], hsCopy); err != nil {
		return nil, err
	}
	return out, nil
}
