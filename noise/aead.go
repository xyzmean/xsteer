// Пакет noise — рукопожатие xsteer: Noise IK, спрятанный внутри ClientHello с обликом Chrome, и
// транспортные ключи, которыми потом шифруются записи данных.
//
// ПОЧЕМУ NOISE IK, А НЕ СВОЁ РАСПИСАНИЕ. Свойства паттерна IK разобраны и доказаны не нами —
// взаимная аутентификация статическими ключами, прямая секретность после второго сообщения,
// скрытие личности инициатора, один круг до данных. Ровно на нём стоит WireGuard. И цепочка
// ключей Noise И ЕСТЬ HKDF: MixKey(x) — это HKDF(ck, x, 2), буква в букву. «Своё расписание»
// дало бы то же самое, но со своей ошибкой в склейке метки, и проверить его было бы нечем.
//
// ОТЛИЧИЙ ОТ ВАНИЛЬНОГО NOISE РОВНО ДВА, и оба — конструкция TLS 1.3, а не изобретение:
//  1. транспортный nonce не плоский счётчик Noise, а iv XOR смещение в потоке (пакет wire);
//  2. Split отдаёт не два ключа по 32 байта, а 88 байт: ключ и iv на каждое направление.
//
// ЧТО ГДЕ ЛЕЖИТ НА ПРОВОДЕ. Ни одного нового расширения и ни одного лишнего байта — всё едет в
// полях, которые у браузера уже есть:
//
//	key_share x25519 (32)  →  эфемерный ключ e, ровно там, где он и был бы в TLS 1.3
//	набивка ECH (176)      →  статический ключ пира под es (32+16) и подтверждение (16);
//	                          остальные 128 байт — случайный шум, как у Chrome без ECH
//	legacy_session_id (32) →  аутентификатор по ВСЕМУ Hello: 16 байт открыто (версия, флаги,
//	                          MTU, время) и 16 байт тега
//	cipher_suites          →  СОГЛАСОВАНИЕ ШИФРА: выбор делает клиент, потому что он один
//	                          знает своё железо
//
// Шифротекст от шума неотличим, поэтому GREASE-ECH настоящего Chrome и наш msg1 внутри него —
// одна и та же строка байтов с точки зрения наблюдателя.
//
// NONCE НОЛЬ ЗАНЯТ ПОДТВЕРЖДЕНИЕМ, И ЭТО ИНВАРИАНТ. Записи данных выводят nonce из смещения в
// потоке, а оно начинается с единицы (начальный номер занят самим SYN). Значит нулевой nonce
// свободен ровно для одной операции на направление — им и подписывается «Finished». Отдельного
// ключа для подтверждения поэтому не нужно, а повтора nonce не возникает.
//
// Порт src/ext/xshake.c. Совпадение с ним обязательно до последнего байта: клиент на десктопе
// разговаривает с тем же хабом, что роутер.
package noise

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD — согласованный шифр. Значения выбраны так, чтобы читаться в отладке, а не совпадать с
// номерами наборов TLS: перевод в номер и обратно живёт в одном месте (SuiteOf, aeadOfSuite).
type AEAD int

const (
	AEADChaCha AEAD = iota
	AEADAES128
)

func (a AEAD) String() string {
	if a == AEADAES128 {
		return "AES-128-GCM"
	}
	return "ChaCha20-Poly1305"
}

// SuiteOf — номер набора TLS 1.3 для этого шифра; им хаб отвечает в ServerHello.
func SuiteOf(a AEAD) uint16 {
	if a == AEADAES128 {
		return 0x1301
	}
	return 0x1303
}

// aeadOfSuite: 0x1301 — AES-128-GCM, всё остальное считаем ChaCha20-Poly1305.
//
// Остальные наборы TLS 1.3 нам не нужны: AES-256 стоит дороже без выигрыша здесь, а CCM
// медленнее обоих. Не отвергаем их, а сводим к ChaCha, потому что список наборов пишет клиент, и
// «непонятный набор» означал бы отказ там, где достаточно выбрать разумное.
func aeadOfSuite(s uint16) AEAD {
	if s == 0x1301 {
		return AEADAES128
	}
	return AEADChaCha
}

// Keys — направление шифрования: развёрнутый шифр и статический iv.
//
// Шифр разворачивается ОДИН РАЗ на направление, а не на запись. В C про это написано отдельно
// (цена setkey), и в Go то же самое: cipher.NewGCM разворачивает таблицы, и делать это на каждый
// пакет означало бы отдать заметную часть процессора под работу, результат которой не меняется.
type Keys struct {
	aead sealer
	iv   [12]byte
	kind AEAD

	// ---- эпохи: периодическая смена ключей без единого байта на проводе (см. epoch.go) ----
	//
	// Пока epochsOn ложно, всё поведение ровно прежнее: те же ключи на всё соединение. Включает
	// его только режим потока, и только после рукопожатия.
	epochsOn bool
	root     [32]byte // корень текущей эпохи; ратчетится вперёд и стирается за собой
	epoch    uint64
	prevAEAD sealer // одна ступень назад: запись на границе эпох не должна стоить обрыва
	prevIV   [12]byte
	prevOK   bool
}

var errCrypto = errors.New("noise: сбой примитива")

func newKeys(kind AEAD, key, iv []byte) (*Keys, error) {
	k := &Keys{kind: kind}
	copy(k.iv[:], iv)
	sl, err := newSealer(kind, key)
	if err != nil {
		return nil, err
	}
	k.aead = sl
	return k, nil
}

// ---- КТО СЧИТАЕТ ШИФР -------------------------------------------------------
//
// Арифметика шифра отделена от всего остального интерфейсом, и это ради одной возможности: отдать
// её ядру, а через ядро — железу. Почему это важно, видно только на замере слабой машины. Живой
// роутер (mt7621, mipsel 24Kc), пакет 1440 байт:
//
//	AES-128-GCM        424 мкс      27 Мбит/с на ядро
//	ChaCha20-Poly1305  268 мкс      43 Мбит/с на ядро
//	сумма TCP           7,2 мкс   1604 Мбит/с на ядро
//
// Криптография там дороже суммы в тридцать семь раз, то есть составляет 97% стоимости пакета.
// Работа над вызовами, копиями и разгрузкой устройства этого не сдвигает вовсе — сдвинуть может
// только другой исполнитель.
//
// ЧТО МЕНЯЕТСЯ НА ПРОВОДЕ: НИЧЕГО. gcm(aes) и rfc7539(chacha20,poly1305) в наборе ядра — те же
// конструкции, что crypto/cipher и x/crypto здесь: те же ключи, те же nonce, те же теги. Поэтому
// движок можно выбирать на каждой стороне свой, и вторая ничего не заметит; поэтому же выбор не
// требует ни согласования, ни ключа в конфигурации на обеих сторонах.

// sealer — исполнитель шифра.
type sealer interface {
	seal(dst, nonce, pt, aad []byte) ([]byte, error)
	open(dst, nonce, ct, aad []byte) ([]byte, error)
	overhead() int
	name() string
	close()
}

// Backend — кто считает шифр.
type Backend int32

const (
	// BackendAuto — решает замер при подъёме (см. Choose). Умолчание.
	BackendAuto Backend = iota
	// BackendGo — только свой код: crypto/cipher и x/crypto.
	BackendGo
	// BackendKernel — только ядро через AF_ALG. Если ядро не умеет — ОТКАЗ, а не тихий возврат к
	// Go: человек, назвавший этот режим, обязан узнать, что он не работает, а не выяснять потом по
	// скорости.
	BackendKernel
)

func (b Backend) String() string {
	switch b {
	case BackendGo:
		return "go"
	case BackendKernel:
		return "ядро"
	}
	return "авто"
}

// chosen — выбранный движок ДЛЯ КАЖДОГО шифра отдельно, по номеру AEAD.
//
// Раздельно, а не одним значением, и это не запас на будущее. Шифр выбирает КЛИЕНТ (он один знает
// своё железо), хаб же обязан считать тем, что назвал клиент, — значит на хабе выбирать шифр нельзя,
// а выбирать исполнителя для каждого из двух можно и нужно. И соотношение у них разное:
// аппаратный ускоритель почти всегда умеет AES и почти никогда ChaCha, а у процессора без AES-NI
// наоборот.
//
// Атомарные: ставятся один раз при подъёме, читаются на каждое рукопожатие.
var chosen [2]atomic.Int32

func slot(a AEAD) int {
	if a == AEADAES128 {
		return 1
	}
	return 0
}

// SetBackend задаёт движок для ОБОИХ шифров. Зовётся ключом командной строки; замер (Choose) ставит
// каждому свой.
func SetBackend(b Backend) {
	chosen[0].Store(int32(b))
	chosen[1].Store(int32(b))
}

// SetBackendFor задаёт движок ОДНОМУ шифру: аппаратный ускоритель почти всегда умеет AES и почти
// никогда ChaCha, поэтому выбор бывает разным для двух.
func SetBackendFor(a AEAD, b Backend) { chosen[slot(a)].Store(int32(b)) }

// BackendFor — что выбрано для этого шифра.
func BackendFor(a AEAD) Backend { return Backend(chosen[slot(a)].Load()) }

func newSealer(kind AEAD, key []byte) (sealer, error) {
	switch BackendFor(kind) {
	case BackendKernel:
		s, err := newKernelSealer(kind, key)
		if err != nil {
			return nil, fmt.Errorf("%w: ядерная криптография запрошена, но недоступна: %v",
				errCrypto, err)
		}
		return s, nil
	}
	// И «go», и «авто» до замера означают свой код. Choose переключает на ядро только когда оно
	// ВЫИГРАЛО замер, поэтому «авто» доходит сюда уже решённым.
	return newGoSealer(kind, key)
}

// goSealer — свой код: crypto/cipher для AES-GCM, x/crypto для ChaCha20-Poly1305.
type goSealer struct {
	a    cipher.AEAD
	kind AEAD
}

func newGoSealer(kind AEAD, key []byte) (sealer, error) {
	g := &goSealer{kind: kind}
	switch kind {
	case AEADAES128:
		b, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errCrypto, err)
		}
		if g.a, err = cipher.NewGCM(b); err != nil {
			return nil, fmt.Errorf("%w: %v", errCrypto, err)
		}
	default:
		var err error
		if g.a, err = chacha20poly1305.New(key[:32]); err != nil {
			return nil, fmt.Errorf("%w: %v", errCrypto, err)
		}
	}
	return g, nil
}

func (g *goSealer) seal(dst, nonce, pt, aad []byte) ([]byte, error) {
	return g.a.Seal(dst, nonce, pt, aad), nil
}

func (g *goSealer) open(dst, nonce, ct, aad []byte) ([]byte, error) {
	return g.a.Open(dst, nonce, ct, aad)
}

func (g *goSealer) overhead() int { return g.a.Overhead() }
func (g *goSealer) name() string  { return "go/" + g.kind.String() }
func (g *goSealer) close()        {}

// Close освобождает ресурсы шифра.
//
// НУЖЕН ИЗ-ЗА ЯДЕРНОГО ДВИЖКА, и это не гигиена. У своего кода освобождать нечего — сборщик мусора
// разберётся, — а ядерный держит ДВА дескриптора на направление. Сессия, ушедшая без Close, теряет
// их навсегда: на хабе со тридцатью пирами и переподключениями это исчерпание предела дескрипторов
// за часы, причём проявится оно не «медленно», а «новые пиры не подключаются».
//
// Зовётся владельцем сессии при её освобождении. Двойной вызов безопасен, вызов на nil — тоже:
// освобождение идёт по путям, где сессия могла не дойти до ключей.
func (k *Keys) Close() {
	if k == nil {
		return
	}
	if k.aead != nil {
		k.aead.close()
		k.aead = nil
	}
	if k.prevAEAD != nil {
		k.prevAEAD.close()
		k.prevAEAD = nil
		k.prevOK = false
	}
}

// Kind — какой шифр согласован. Нужен журналу при подъёме туннеля: разница между шифрами на
// слабом процессоре измеряется разами, и знать это надо ДО замеров, а не после.
func (k *Keys) Kind() AEAD { return k.kind }

// nonce = iv XOR seq, ровно как в TLS 1.3 (RFC 8446 §5.3). Совпадение с wire.Nonce обязательно —
// там тот же вывод для 32-битного смещения, и тест сверяет их между собой.
func (k *Keys) nonce(seq uint64) [12]byte { return k.nonceWith(k.iv, seq) }

// nonceWith — тот же вывод, но на названном iv: нужен прошлой эпохе, у которой свой iv.
func (k *Keys) nonceWith(iv [12]byte, seq uint64) [12]byte {
	n := iv
	for i := 0; i < 8; i++ {
		n[11-i] ^= byte(seq >> (8 * i))
	}
	return n
}

// Seal шифрует НА МЕСТЕ: шифротекст с тегом ложится туда, где лежал открытый текст, и буфер
// обязан иметь запас в wire.Tag байт за ним.
//
// Это не микрооптимизация, а требование раскладки: заголовки пишутся ПЕРЕД нагрузкой в том же
// буфере, и пакет уходит с того места, где уже лежит шифротекст, — без единой копии на пакет.
// Go позволяет так делать: dst = buf[:0] при plaintext = buf[:n] задокументировано как
// переиспользование памяти.
func (k *Keys) Seal(buf []byte, n int, aad []byte, seq uint64) ([]byte, error) {
	if cap(buf) < n+k.aead.overhead() {
		return nil, fmt.Errorf("noise: буфер без места под тег")
	}
	// Эпоха записи определяется её смещением, и получатель посчитает ту же самую: номер эпохи
	// нигде не передаётся.
	if k.epochsOn {
		if err := k.toEpoch(epochOf(seq)); err != nil {
			return nil, err
		}
	}
	nc := k.nonce(seq)
	return k.aead.seal(buf[:0], nc[:], buf[:n], aad)
}

// Open расшифровывает НА МЕСТЕ и возвращает открытый текст.
//
// ErrAuth от всех прочих ошибок отделена намеренно: «тег не сошёлся» — это чужой или
// подделанный пакет, его отбрасывают счётчиком и соединение НЕ рвут. Спутать это с «сломался
// шифр» значило бы рвать туннель от одного случайного пакета с публичного порта.
func (k *Keys) Open(buf []byte, aad []byte, seq uint64) ([]byte, error) {
	if k.epochsOn {
		e := epochOf(seq)
		switch {
		case e == k.epoch:
			// обычный случай — текущая эпоха
		case k.prevOK && e+1 == k.epoch:
			// Запись прошлой эпохи: расшифровываем прошлым ключом и НЕ откатываем состояние.
			nc := k.nonceWith(k.prevIV, seq)
			out, err := k.prevAEAD.open(buf[:0], nc[:], buf, aad)
			if err != nil {
				return nil, ErrAuth
			}
			return out, nil
		case e > k.epoch:
			if err := k.toEpoch(e); err != nil {
				return nil, err
			}
		default:
			// Слишком старая эпоха: её ключи стёрты — в этом и смысл ратчета.
			return nil, ErrAuth
		}
	}
	nc := k.nonce(seq)
	out, err := k.aead.open(buf[:0], nc[:], buf, aad)
	if err != nil {
		return nil, ErrAuth
	}
	return out, nil
}
