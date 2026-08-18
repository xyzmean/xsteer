package noise

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/xyzmean/xsteer/chello"
	"github.com/xyzmean/xsteer/wire"
)

// ProtoVer — версия протокола на проводе. Едет в подписанной части, и несовпадение называется
// отдельной ошибкой: «другая версия» и «не сошёлся тег» требуют разных действий.
const ProtoVer = 1

// Отказы. Разные НАРОЧНО: «не сошёлся тег» и «это не наш клиент» требуют разного, а один код на
// всё означает «не работает, и почему — неизвестно».
var (
	ErrFormat  = errors.New("noise: не наша форма рукопожатия")
	ErrAuth    = errors.New("noise: тег не сошёлся — не наш собеседник")
	ErrCrypto  = errors.New("noise: сбой примитива или источника случайности")
	ErrPeer    = errors.New("noise: пир опознан, но его нет в конфигурации")
	ErrReplay  = errors.New("noise: метка времени не новее прошлой от этого пира")
	ErrSmall   = errors.New("noise: не влезло в буфер")
	ErrVersion = errors.New("noise: другая версия протокола на той стороне")
)

// Имена протокола Noise. Для ChaCha имя ровно 32 символа, то есть h инициализируется без
// хеширования — мелочь, обещанная спецификацией. Для AES-GCM короче, и тогда добивается нулями
// (тоже по спецификации). Имена РАЗНЫЕ у разных шифров нарочно: это привязка транскрипта к
// согласованному AEAD, без которой посредник, переписавший порядок наборов в Hello, остался бы
// незамеченным.
const (
	nameChaCha = "Noise_IK_25519_ChaChaPoly_SHA256"
	nameAES    = "Noise_IK_25519_AESGCM_SHA256"
	// Пролог: версия формата. Разные версии не должны давать сходящиеся транскрипты — иначе
	// будущая правка формата выглядела бы как «ключи не те», а не как «другая версия».
	prologue = "xsteer/1"
)

// Длины на проводе. Собраны здесь, потому что обе стороны обязаны считать одинаково, а
// «посчитаю на месте» — это два места, где можно ошибиться по-разному.
const (
	encStatic = 32 + wire.Tag // статический ключ пира под es
	encEmpty  = wire.Tag      // пустая нагрузка: только тег
	echUsed   = encStatic + encEmpty
	sidPlain  = 16                    // открытая часть аутентификатора
	finPlain  = 37                    // транскрипт(32) + версия(1) + запас(4)
	finBody   = finPlain + wire.Tag   // 53
	finRec    = wire.RecHdr + finBody // 58 — как у настоящего Finished
	certMin   = 600                   // «сертификат» случайной длины: постоянная стала бы отпечатком
	certMax   = 1100
)

// FinBody — длина нагрузки подтверждения («Finished»). Наружу нужна режиму потока: там ответ хаба
// читается запись за записью, и конец узнаётся по этой длине.
const FinBody = finBody

// Payload — полезная нагрузка рукопожатия: 16 байт, помещающихся в аутентификатор session_id.
//
// MTU едет ЗДЕСЬ, а не отдельным служебным кадром: рассогласование MTU — самый трудный в
// диагностике класс отказов («маленькие пакеты ходят, большие пропадают»), и узнать о нём надо
// до того, как пойдёт первый пакет, а не после.
type Payload struct {
	Ver uint8
	// Flags: младшие три бита — НОМЕР СОЕДИНЕНИЯ (0..wire.ConnsMax-1). Он едет внутри
	// аутентификатора, то есть на проводе не виден и подделке не подлежит; хабу он нужен, чтобы
	// положить сессию на своё место в наборе пира, а не вытеснить соседнюю.
	Flags uint8
	MTU   uint16 // MTU туннеля на этой стороне
	Stamp uint64 // секунды эпохи: защита от воспроизведения msg1
}

func (p *Payload) pack(out []byte, rnd io.Reader) error {
	out[0] = p.Ver
	out[1] = p.Flags
	binary.BigEndian.PutUint16(out[2:4], p.MTU)
	binary.BigEndian.PutUint64(out[4:12], p.Stamp)
	// Четыре байта запаса — случайные, а не нулевые: постоянные нули в подписанном блоке дали бы
	// наблюдателю известный открытый текст в фиксированном месте.
	if _, err := io.ReadFull(rnd, out[12:16]); err != nil {
		return ErrCrypto
	}
	return nil
}

func unpackPayload(in []byte) Payload {
	return Payload{
		Ver:   in[0],
		Flags: in[1],
		MTU:   binary.BigEndian.Uint16(in[2:4]),
		Stamp: binary.BigEndian.Uint64(in[4:12]),
	}
}

// ConnID — номер соединения из принятой нагрузки.
func (p Payload) ConnID() int { return int(p.Flags & 0x07) }

// FlagSplit — «умею собирать запись, разрезанную между сегментами».
//
// Бит в ПОДПИСАННОЙ части рукопожатия, а не отдельное поле: место в аутентификаторе уже есть, а
// новое поле на проводе стоило бы байт и было бы видно. Сторона, которая про этот бит не знает
// (реализация на C маскирует flags как 0x07), его не выставит — и разрезанного не получит.
const FlagSplit = 0x08

// CanSplit — согласована ли сборка разрезанных записей.
func (p Payload) CanSplit() bool { return p.Flags&FlagSplit != 0 }

// HS — состояние рукопожатия. Живёт от начала до Split и обнуляется сразу после.
type HS struct {
	h    [32]byte // транскрипт
	ck   [32]byte // цепочка ключей
	k    *Keys    // ключ текущего шага
	aead AEAD

	ePriv, ePub [32]byte
	// sPriv — наш СТАТИЧЕСКИЙ приватный: он нужен на шаге se, то есть уже после сборки Hello.
	// Хранится здесь, чтобы вызывающему не приходилось держать секрет живым до конца
	// рукопожатия; обнуляется Wipe вместе со всем остальным.
	sPriv [32]byte
	// PeerStatic — статический публичный ИНИЦИАТОРА, расшифрованный из msg1. Заполняет только
	// хаб: ему этот ключ нужен на шаге se, и он же — личность пира.
	PeerStatic [32]byte
	rs         [32]byte // статический публичный второй стороны (у хаба — свой)
	sid        [32]byte // аутентификатор: у клиента отправленный, у хаба принятый
	// Peer — что прислала вторая сторона. Читается вызывающим: MTU нужен согласованию, номер
	// соединения — раскладке по воркерам, метка времени — защите от воспроизведения.
	Peer     Payload
	roleInit bool

	rnd io.Reader
}

func (hs *HS) random(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(hs.rnd, b); err != nil {
		return nil, ErrCrypto
	}
	return b, nil
}

// Wipe обнуляет состояние. Обязательно после Split: в нём лежат ck и ключ шага, из которых
// выводятся транспортные ключи.
func (hs *HS) Wipe() {
	*hs = HS{}
}

func (hs *HS) mixHash(data ...[]byte) {
	s := sha256.New()
	s.Write(hs.h[:])
	for _, d := range data {
		s.Write(d)
	}
	s.Sum(hs.h[:0])
}

// mixKey: MixKey(ikm) = HKDF(ck, ikm, 2) — ck' и ключ шага одним расширением на 64 байта.
//
// Совпадение с определением Noise точное, и именно поэтому здесь нет своего HMAC:
// HKDF-Expand(prk, "", 64) даёт T1||T2, где T1 = HMAC(prk, 0x01) и T2 = HMAC(prk, T1||0x02) —
// буква в букву цепочка Noise. Тест сверяет это с независимым подсчётом, потому что «должно
// совпадать» и «совпадает» — разные утверждения.
func (hs *HS) mixKey(ikm []byte) error {
	prk := hkdf.Extract(sha256.New, ikm, hs.ck[:])
	var out [64]byte
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, nil), out[:]); err != nil {
		return ErrCrypto
	}
	copy(hs.ck[:], out[:32])
	// iv нулевой: nonce в Noise — счётчик шага, а он на каждом шаге начинается заново, потому что
	// ключ на каждом шаге новый. Ноль здесь не «забыли заполнить», а ровно то, что предписывает
	// Noise.
	k, err := newKeys(hs.aead, out[32:64], make([]byte, 12))
	if err != nil {
		return err
	}
	hs.k = k
	return nil
}

// encryptAndHash шифрует и вбирает результат в транскрипт. AAD — текущий h, как требует Noise.
func (hs *HS) encryptAndHash(dst, plain []byte) error {
	n := copy(dst, plain)
	ct, err := hs.k.Seal(dst[:n+wire.Tag], n, hs.h[:], 0)
	if err != nil {
		return err
	}
	hs.mixHash(ct)
	return nil
}

// decryptAndHash расшифровывает и вбирает в транскрипт ПРИСЛАННЫЕ байты — иначе стороны получат
// разные h и разойдутся на следующем же шаге.
func (hs *HS) decryptAndHash(ct []byte) ([]byte, error) {
	if len(ct) < wire.Tag {
		return nil, ErrFormat
	}
	tmp := make([]byte, len(ct))
	copy(tmp, ct)
	plain, err := hs.k.Open(tmp, hs.h[:], 0)
	if err != nil {
		return nil, ErrAuth
	}
	hs.mixHash(ct)
	return plain, nil
}

// split — транспортные ключи. Восемьдесят восемь байт одним расширением: ключ и iv на каждое
// направление. Направления названы от инициатора: i2r и r2i.
func (hs *HS) split() (i2r, r2i *Keys, err error) {
	prk := hkdf.Extract(sha256.New, nil, hs.ck[:])
	var out [88]byte
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("xsteer split")), out[:]); err != nil {
		return nil, nil, ErrCrypto
	}
	if i2r, err = newKeys(hs.aead, out[0:32], out[32:44]); err != nil {
		return nil, nil, err
	}
	if r2i, err = newKeys(hs.aead, out[44:76], out[76:88]); err != nil {
		return nil, nil, err
	}
	// Ключ шага больше не нужен: Split — его последнее применение.
	hs.k = nil
	return i2r, r2i, nil
}

// authKey — ключ аутентификатора session_id: отдельный, выведенный из цепочки.
//
// Отдельный потому, что этой же операцией шифруется полезная нагрузка Noise, и переиспользовать
// ключ с тем же нулевым nonce означало бы повтор пары «ключ, nonce» — то есть полную потерю
// защиты.
func (hs *HS) authKey() (*Keys, error) {
	prk := hkdf.Extract(sha256.New, nil, hs.ck[:])
	var out [44]byte
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, []byte("xsteer auth")), out[:]); err != nil {
		return nil, ErrCrypto
	}
	return newKeys(hs.aead, out[0:32], out[32:44])
}

func (hs *HS) begin(a AEAD, rs [32]byte, rnd io.Reader) {
	*hs = HS{aead: a, rs: rs, rnd: rnd}
	if hs.rnd == nil {
		hs.rnd = rand.Reader
	}
	name := nameChaCha
	if a == AEADAES128 {
		name = nameAES
	}
	// Короче 32 — добить нулями, как предписывает Noise; длиннее — хешировать (наши имена
	// короче, поэтому второй ветки нет и заводить её незачем).
	copy(hs.h[:], name)
	hs.ck = hs.h
	hs.mixHash([]byte(prologue))
	// IK: статический публичный ключ отвечающего известен инициатору заранее и входит в
	// транскрипт как предварительное сообщение. Именно это связывает рукопожатие с КОНКРЕТНЫМ
	// хабом: тот же Hello, отправленный другому, не сойдётся.
	hs.mixHash(hs.rs[:])
}

// dh — общий секрет X25519.
//
// curve25519.X25519 возвращает ошибку на точках малого порядка, чего mbedtls не делает. Это
// отличие в сторону строгости, и оставлено намеренно: нулевой общий секрет означает либо
// подсунутый ключ, либо испорченную конфигурацию, и продолжать рукопожатие в обоих случаях
// незачем.
func dh(priv, peer [32]byte) ([32]byte, error) {
	var out [32]byte
	s, err := curve25519.X25519(priv[:], peer[:])
	if err != nil {
		return out, ErrCrypto
	}
	copy(out[:], s)
	return out, nil
}

func pubOf(priv [32]byte) ([32]byte, error) {
	var out [32]byte
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return out, ErrCrypto
	}
	copy(out[:], p)
	return out, nil
}

// ---- клиент ----------------------------------------------------------------

// ClientHello собирает ClientHello, несущий msg1, и возвращает готовую запись TLS.
//
// aesPreferred решает, какой шифр будет согласован: порядок наборов в Hello и есть согласование.
// Решает клиент, потому что узкое место всегда его процессор, а не сервер.
func (hs *HS) ClientHello(priv, hubPub [32]byte, sni string, mtu, connID int,
	aesPreferred, pq bool, rnd io.Reader) ([]byte, error) {

	a := AEADChaCha
	if aesPreferred {
		a = AEADAES128
	}
	hs.begin(a, hubPub, rnd)
	hs.roleInit = true

	e, err := hs.random(32)
	if err != nil {
		return nil, err
	}
	copy(hs.ePriv[:], e)
	if hs.ePub, err = pubOf(hs.ePriv); err != nil {
		return nil, err
	}
	// Публичная половина нашего СТАТИЧЕСКОГО ключа выводится из приватного, а не хранится рядом с
	// ним: два значения, выведенных одно из другого, обязаны считаться.
	ourPub, err := pubOf(priv)
	if err != nil {
		return nil, err
	}
	hs.sPriv = priv

	pay := Payload{
		Ver:   ProtoVer,
		Flags: byte(connID & 0x07),
		MTU:   uint16(mtu),
		Stamp: uint64(time.Now().Unix()),
	}

	var inner error
	car := &chello.Carrier{Pub: hs.ePub}
	// Вся работа msg1 по Noise делается ЗДЕСЬ, потому что ровно здесь впервые есть общий секрет
	// es и ещё не собран Hello.
	car.FillECH = func(payload []byte) error {
		if len(payload) < echUsed {
			inner = ErrSmall
			return inner
		}
		es, err := dh(hs.ePriv, hs.rs)
		if err != nil {
			inner = err
			return err
		}
		hs.mixHash(hs.ePub[:]) // e
		if err := hs.mixKey(es[:]); err != nil {
			inner = err
			return err
		} // es
		if err := hs.encryptAndHash(payload[:encStatic], ourPub[:]); err != nil {
			inner = err
			return err
		} // s
		ss, err := dh(priv, hs.rs)
		if err != nil {
			inner = err
			return err
		}
		if err := hs.mixKey(ss[:]); err != nil {
			inner = err
			return err
		} // ss
		// Пустая нагрузка: один тег. Всё содержательное (версия, MTU, время) едет в
		// аутентификаторе session_id — он и так подписывает весь Hello, значит второй экземпляр
		// тех же полей был бы лишними байтами.
		if err := hs.encryptAndHash(payload[encStatic:echUsed], nil); err != nil {
			inner = err
			return err
		}
		// Остаток набивки — случайный, как у браузера без настроенного ECH. Шифротекст от шума
		// неотличим, поэтому граница между нашими 64 байтами и шумом снаружи не видна.
		if _, err := io.ReadFull(hs.rnd, payload[echUsed:]); err != nil {
			inner = ErrCrypto
			return inner
		}
		return nil
	}
	car.FillSID = func(sid, hsmsg []byte) error {
		ak, err := hs.authKey()
		if err != nil {
			inner = err
			return err
		}
		var plain [sidPlain]byte
		if err := pay.pack(plain[:], hs.rnd); err != nil {
			inner = err
			return err
		}
		copy(sid, plain[:])
		if _, err := ak.Seal(sid[:sidPlain+wire.Tag], sidPlain, hsmsg, 0); err != nil {
			inner = err
			return err
		}
		return nil
	}

	rec, err := chello.BuildOpt(sni, aesPreferred, pq, car, hs.rnd)
	if err != nil {
		if inner != nil {
			return nil, inner
		}
		return nil, err
	}

	// Транскрипт вбирает ГОТОВОЕ сообщение рукопожатия — вместе с настоящим session_id и вместе
	// со всей формой Hello. Значит подмена любого байта конверта (порядка наборов шифров,
	// расширений, SNI) сломает подтверждение, а не пройдёт незамеченной.
	ref, err := chello.Parse(rec)
	if err != nil {
		return nil, ErrFormat
	}
	copy(hs.sid[:], rec[ref.SIDOff:ref.SIDOff+32])
	hs.mixHash(rec[ref.HSOff : ref.HSOff+ref.HSLen])
	return rec, nil
}

// ClientFinish разбирает ответ хаба (ServerHello + ChangeCipherSpec + две записи) и отдаёт
// транспортные ключи. consumed — сколько байт потока израсходовано; остаток принадлежит уже
// данным.
func (hs *HS) ClientFinish(in []byte) (tx, rx *Keys, consumed int, err error) {
	if len(in) < 5 || in[0] != 0x16 {
		return nil, nil, 0, ErrFormat
	}
	shLen := int(in[3])<<8 | int(in[4])
	if len(in) < 5+shLen {
		return nil, nil, 0, ErrFormat
	}
	sh := in[5 : 5+shLen]
	if shLen < 4+2+32+1+32+2+1+2 || sh[0] != 0x02 {
		return nil, nil, 0, ErrFormat
	}
	if sh[4+2+32] != 32 {
		return nil, nil, 0, ErrFormat
	}
	// Эхо session_id — обязанность настоящего сервера TLS 1.3, и по нему же клиент узнаёт, что
	// отвечают именно ему. Сравнение постоянного времени: подсказывать по времени ответа, сколько
	// байт сошлось, незачем.
	if subtle.ConstantTimeCompare(sh[4+2+32+1:4+2+32+1+32], hs.sid[:]) != 1 {
		return nil, nil, 0, ErrAuth
	}
	suite := uint16(sh[4+2+32+1+32])<<8 | uint16(sh[4+2+32+1+32+1])
	if aeadOfSuite(suite) != hs.aead {
		return nil, nil, 0, ErrFormat
	}
	// Ключ обмена ищем разбором расширений: их порядок задаёт сервер.
	p := 4 + 2 + 32 + 1 + 32 + 2 + 1
	extN := int(sh[p])<<8 | int(sh[p+1])
	p += 2
	if p+extN > shLen {
		return nil, nil, 0, ErrFormat
	}
	var peerE [32]byte
	found := false
	for e := p; e+4 <= p+extN; {
		t := int(sh[e])<<8 | int(sh[e+1])
		l := int(sh[e+2])<<8 | int(sh[e+3])
		if e+4+l > p+extN {
			return nil, nil, 0, ErrFormat
		}
		if t == 0x0033 && l == 36 && sh[e+4] == 0x00 && sh[e+5] == 0x1D {
			copy(peerE[:], sh[e+8:e+40])
			found = true
		}
		e += 4 + l
	}
	if !found {
		return nil, nil, 0, ErrFormat
	}

	hs.mixHash(sh)
	ee, err := dh(hs.ePriv, peerE)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := hs.mixKey(ee[:]); err != nil {
		return nil, nil, 0, err
	}
	// se со стороны клиента: его СТАТИЧЕСКИЙ и эфемерный сервера.
	se, err := dh(hs.sPriv, peerE)
	if err != nil {
		return nil, nil, 0, err
	}
	if err := hs.mixKey(se[:]); err != nil {
		return nil, nil, 0, err
	}
	i := 5 + shLen

	// ChangeCipherSpec — пропускаем, он фальшивый у обеих сторон.
	if i+6 <= len(in) && in[i] == 0x14 {
		i += 6
	}

	// Запись формы «Certificate»: наша нагрузка в начале, дальше набивка.
	if i+wire.RecHdr > len(in) || in[i] != 0x17 {
		return nil, nil, 0, ErrFormat
	}
	clen := int(in[i+3])<<8 | int(in[i+4])
	if i+wire.RecHdr+clen > len(in) || clen < sidPlain+wire.Tag {
		return nil, nil, 0, ErrFormat
	}
	cbody := in[i+wire.RecHdr:]
	plain, err := hs.decryptAndHash(cbody[:sidPlain+wire.Tag])
	if err != nil {
		return nil, nil, 0, err
	}
	hs.Peer = unpackPayload(plain)
	if hs.Peer.Ver != ProtoVer {
		return nil, nil, 0, ErrVersion
	}
	// Набивка входит в транскрипт, поэтому её подмена ломает подтверждение, а не проходит молча.
	hs.mixHash(cbody[sidPlain+wire.Tag : clen])
	i += wire.RecHdr + clen

	if tx, rx, err = hs.split(); err != nil {
		return nil, nil, 0, err
	}

	// Подтверждение хаба проверяется не только тегом, но и РАВЕНСТВОМ транскрипта: тег без этого
	// сказал бы «не сошлось», а равенство говорит «не сошлось ИМЕННО здесь».
	if i+finRec > len(in) || in[i] != 0x17 {
		return nil, nil, 0, ErrFormat
	}
	flen := int(in[i+3])<<8 | int(in[i+4])
	if flen != finBody || i+wire.RecHdr+flen > len(in) {
		return nil, nil, 0, ErrFormat
	}
	fin := make([]byte, flen)
	copy(fin, in[i+wire.RecHdr:i+wire.RecHdr+flen])
	got, err := rx.Open(fin, hs.h[:], 0)
	if err != nil {
		return nil, nil, 0, ErrAuth
	}
	if subtle.ConstantTimeCompare(got[:32], hs.h[:]) != 1 {
		return nil, nil, 0, ErrAuth
	}
	i += wire.RecHdr + flen
	return tx, rx, i, nil
}

// ClientConfirm собирает своё подтверждение («Finished»). Отправляется сразу за разбором ответа.
//
// Оно нужно по существу, а не для облика: msg1 доказывает владение статическим ключом, но
// записанный msg1 можно воспроизвести. Метка времени проверяется тоже, но честная формулировка
// такая: воспроизведённый msg1 не даёт атакующему сессию, он даёт хабу зря потраченные три
// X25519.
func (hs *HS) ClientConfirm(tx *Keys) ([]byte, error) {
	out := make([]byte, finRec)
	out[0], out[1], out[2] = 0x17, 0x03, 0x03
	out[3], out[4] = byte(finBody>>8), byte(finBody)
	copy(out[wire.RecHdr:], hs.h[:])
	out[wire.RecHdr+32] = ProtoVer
	if _, err := tx.Seal(out[wire.RecHdr:], finPlain, hs.h[:], 0); err != nil {
		return nil, err
	}
	return out, nil
}

// ---- хаб --------------------------------------------------------------------

// ServerRead разбирает ClientHello и узнаёт, чей это пир: PeerStatic получает 32 байта
// статического ключа инициатора, по которому вызывающий ищет пира в своей таблице.
//
// Хаб делает это ПОСЛЕ расшифровки, и это лучше альтернативы: явный индекс пира на проводе
// раскрывал бы постоянный идентификатор на фиксированном смещении в каждом рукопожатии — ровно
// тот признак, по которому опознаётся WireGuard, — и стоил бы байт.
func (hs *HS) ServerRead(priv [32]byte, rec []byte, rnd io.Reader) error {
	ref, err := chello.Parse(rec)
	if err != nil {
		return ErrFormat
	}
	if ref.ECHOff == 0 || ref.ECHLen < echUsed || ref.Suite == 0 {
		return ErrFormat
	}
	ourPub, err := pubOf(priv)
	if err != nil {
		return err
	}
	hs.begin(aeadOfSuite(ref.Suite), ourPub, rnd)
	hs.sPriv = priv
	hs.roleInit = false
	copy(hs.ePub[:], rec[ref.KSOff:ref.KSOff+32])

	// es считается НАШИМ статическим и ЕГО эфемерным — то же значение, что у него.
	es, err := dh(priv, hs.ePub)
	if err != nil {
		return err
	}
	hs.mixHash(hs.ePub[:])
	if err := hs.mixKey(es[:]); err != nil {
		return err
	}

	// Личность инициатора приезжает зашифрованной — расшифровываем и только потом ищем её в
	// таблице пиров.
	ps, err := hs.decryptAndHash(rec[ref.ECHOff : ref.ECHOff+encStatic])
	if err != nil {
		return err
	}
	copy(hs.PeerStatic[:], ps)
	ss, err := dh(priv, hs.PeerStatic)
	if err != nil {
		return err
	}
	if err := hs.mixKey(ss[:]); err != nil {
		return err
	}
	if _, err := hs.decryptAndHash(rec[ref.ECHOff+encStatic : ref.ECHOff+echUsed]); err != nil {
		return err
	}

	// Аутентификатор session_id: по нему же читаются версия, MTU и метка времени. Считается над
	// сообщением рукопожатия с ОБНУЛЁННЫМ session_id — теми самыми байтами, что подписывал
	// клиент.
	aad := make([]byte, ref.HSLen)
	copy(aad, rec[ref.HSOff:ref.HSOff+ref.HSLen])
	for i := 0; i < 32; i++ {
		aad[ref.SIDOff-ref.HSOff+i] = 0
	}
	ak, err := hs.authKey()
	if err != nil {
		return err
	}
	sid := make([]byte, 32)
	copy(sid, rec[ref.SIDOff:ref.SIDOff+32])
	plain, err := ak.Open(sid, aad, 0)
	if err != nil {
		return ErrAuth
	}
	hs.Peer = unpackPayload(plain)
	if hs.Peer.Ver != ProtoVer {
		return ErrVersion
	}
	copy(hs.sid[:], rec[ref.SIDOff:ref.SIDOff+32])
	hs.mixHash(rec[ref.HSOff : ref.HSOff+ref.HSLen])
	return nil
}

// buildServerHello — ServerHello с эхом session_id и нашим эфемерным ключом. Эхо — обязанность
// настоящего сервера TLS 1.3, и оно бесплатно; отсутствие эха было бы отличием от всякого
// настоящего сервера в первом же ответе.
func (hs *HS) buildServerHello(suite uint16, random []byte) []byte {
	w := make([]byte, 0, 160)
	w = append(w, 0x16, 0x03, 0x03, 0, 0)
	hsAt := len(w)
	w = append(w, 0x02, 0, 0, 0)
	w = append(w, 0x03, 0x03)
	w = append(w, random...)
	w = append(w, 32)
	w = append(w, hs.sid[:]...)
	w = append(w, byte(suite>>8), byte(suite))
	w = append(w, 0x00) // без сжатия
	extAt := len(w)
	w = append(w, 0, 0)
	// supported_versions: 1.3
	w = append(w, 0x00, 0x2B, 0x00, 0x02, 0x03, 0x04)
	// key_share: x25519 и наш эфемерный ключ
	w = append(w, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20)
	w = append(w, hs.ePub[:]...)
	extN := len(w) - extAt - 2
	w[extAt], w[extAt+1] = byte(extN>>8), byte(extN)
	hsN := len(w) - hsAt - 4
	w[hsAt+1], w[hsAt+2], w[hsAt+3] = byte(hsN>>16), byte(hsN>>8), byte(hsN)
	recN := len(w) - 5
	w[3], w[4] = byte(recN>>8), byte(recN)
	return w
}

// ServerWrite собирает ответный поток и отдаёт транспортные ключи.
func (hs *HS) ServerWrite(mtu int) (out []byte, tx, rx *Keys, err error) {
	suite := SuiteOf(hs.aead)
	// ПОРЯДОК ЗДЕСЬ ВАЖЕН И НЕОЧЕВИДЕН. В hs.ePub сейчас лежит эфемерный ключ КЛИЕНТА,
	// прочитанный из его Hello, и он нужен для ee. Своя пара генерируется только после того, как
	// чужой ключ сохранён: первая версия этого кода в C генерировала пару сразу и затирала его,
	// после чего ee у сторон не совпадал — то есть рукопожатие «проходило» и разъезжалось на
	// подтверждении.
	peerE := hs.ePub
	e, err := hs.random(32)
	if err != nil {
		return nil, nil, nil, err
	}
	copy(hs.ePriv[:], e)
	if hs.ePub, err = pubOf(hs.ePriv); err != nil {
		return nil, nil, nil, err
	}

	random, err := hs.random(32)
	if err != nil {
		return nil, nil, nil, err
	}
	out = hs.buildServerHello(suite, random)
	// Транскрипт вбирает ВСЁ сообщение ServerHello, а не только ключ: так подмена любого поля
	// ответа (набора шифров, версии) ломает подтверждение.
	hs.mixHash(out[5:])

	ee, err := dh(hs.ePriv, peerE)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := hs.mixKey(ee[:]); err != nil {
		return nil, nil, nil, err
	}
	// se: наш эфемерный и СТАТИЧЕСКИЙ инициатора. Именно этот шаг аутентифицирует клиента — без
	// него любой, кто перехватил его Hello, мог бы выдать себя за него.
	se, err := dh(hs.ePriv, hs.PeerStatic)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := hs.mixKey(se[:]); err != nil {
		return nil, nil, nil, err
	}

	// Фальшивый ChangeCipherSpec: настоящий TLS 1.3 его посылает ради посредников, и его
	// отсутствие было бы отличием. Шесть байт.
	out = append(out, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)

	// Запись формы «Certificate»: наша нагрузка плюс случайная набивка правдоподобной длины.
	// Длина СЛУЧАЙНАЯ, потому что постоянная сама стала бы отпечатком; и она невелика, потому что
	// весь ответ обязан влезть в один сегмент.
	rnd2, err := hs.random(2)
	if err != nil {
		return nil, nil, nil, err
	}
	pad := certMin + int(uint16(rnd2[0])<<8|uint16(rnd2[1]))%(certMax-certMin)
	body := sidPlain + wire.Tag + pad
	out = append(out, 0x17, 0x03, 0x03, byte(body>>8), byte(body))
	var plain [sidPlain]byte
	mine := Payload{Ver: ProtoVer, MTU: uint16(mtu), Stamp: uint64(time.Now().Unix())}
	if err := mine.pack(plain[:], hs.rnd); err != nil {
		return nil, nil, nil, err
	}
	cell := make([]byte, sidPlain+wire.Tag)
	if err := hs.encryptAndHash(cell, plain[:]); err != nil {
		return nil, nil, nil, err
	}
	out = append(out, cell...)
	padding, err := hs.random(pad)
	if err != nil {
		return nil, nil, nil, err
	}
	hs.mixHash(padding)
	out = append(out, padding...)

	// У хаба rx — от клиента (i2r), tx — к нему (r2i).
	rx, tx, err = hs.split()
	if err != nil {
		return nil, nil, nil, err
	}

	// Подтверждение под транспортным ключом и НУЛЕВЫМ nonce. Ноль свободен по построению: записи
	// данных выводят nonce из смещения в потоке, а оно начинается с единицы.
	fin := make([]byte, finPlain+wire.Tag)
	copy(fin, hs.h[:])
	fin[32] = ProtoVer
	if _, err := tx.Seal(fin, finPlain, hs.h[:], 0); err != nil {
		return nil, nil, nil, err
	}
	out = append(out, 0x17, 0x03, 0x03, byte(finBody>>8), byte(finBody))
	out = append(out, fin...)
	return out, tx, rx, nil
}

// ServerConfirm проверяет подтверждение клиента.
func (hs *HS) ServerConfirm(rx *Keys, in []byte) (consumed int, err error) {
	if len(in) < finRec || in[0] != 0x17 {
		return 0, ErrFormat
	}
	flen := int(in[3])<<8 | int(in[4])
	if flen != finBody || wire.RecHdr+flen > len(in) {
		return 0, ErrFormat
	}
	fin := make([]byte, flen)
	copy(fin, in[wire.RecHdr:wire.RecHdr+flen])
	got, err := rx.Open(fin, hs.h[:], 0)
	if err != nil {
		return 0, ErrAuth
	}
	if subtle.ConstantTimeCompare(got[:32], hs.h[:]) != 1 {
		return 0, ErrAuth
	}
	return wire.RecHdr + flen, nil
}

// Alert отказывает неузнанному так, как это сделал бы настоящий сервер TLS: fatal
// handshake_failure. Честно говоря, от активного зондирования это не спасает — но молчание в
// ответ на настоящий ClientHello отличимо ещё сильнее.
func Alert() []byte {
	return []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}
}
