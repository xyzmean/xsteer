//go:build linux

package noise

// ЯДЕРНАЯ КРИПТОГРАФИЯ ЧЕРЕЗ AF_ALG — единственная поддерживаемая дверь из пользовательского
// пространства к тому, что умеет ядро и железо под ним.
//
// ЗАЧЕМ ЭТО ВООБЩЕ. Замер на живом роутере (mt7621, mipsel 24Kc, Go 1.25) на пакете 1440 байт:
//
//	AES-128-GCM        424 мкс   3,4 МБ/с    27 Мбит/с на ядро
//	ChaCha20-Poly1305  268 мкс   5,4 МБ/с    43 Мбит/с на ядро
//	сумма TCP           7,2 мкс  200 МБ/с  1604 Мбит/с на ядро
//
// То есть на роутере криптография — это не «горячий путь наряду с прочим», это 97% стоимости
// пакета: она дороже суммы в тридцать семь раз. Никакая работа над вызовами, копиями и разгрузкой
// устройства этого не сдвинет. Сдвинуть может только другой исполнитель шифра.
//
// ЧТО МОЖЕТ ЯДРО, А ЧЕГО НЕ МОЖЕТ. Модуль wireguard (и amneziawg) НЕ отдаёт свою криптографию
// наружу: интерфейса для этого у него нет и не предполагалось. Но он тянет за собой
// kmod-crypto-lib-chacha20poly1305, а тот регистрирует chacha20poly1305 в общем наборе ядра — и
// вот ДО НЕГО пользовательское пространство дотянуться может, через AF_ALG. Там же живёт и
// аппаратный ускоритель, если он есть: на том же mt7621 драйвер crypto_hw_eip93 регистрирует
// ctr(aes-eip93) и cbc(aes-eip93) с приоритетом 1500, то есть AES считает микросхема, а не
// процессор.
//
// ПОЧЕМУ ЭТО НЕ ЗАМЕНА, А ВЫБОР ПО ЗАМЕРУ. Цена AF_ALG — два системных вызова на операцию плюс
// сборка списка страниц в ядре. На x86 с аппаратным AES это заведомо проигрыш: 362 нс у Go против
// заведомо большего у пары вызовов. На роутере — заведомо неизвестно: аппаратный AES там медленный
// и один на все ядра, а kmod может быть и не установлен. Единственный честный ответ — измерить оба
// пути на той машине, где туннель работает, и выбрать победителя. Ровно это делает Choose.
//
// ФОРМАТ НА ПРОВОДЕ НЕ МЕНЯЕТСЯ НИ НА БАЙТ. gcm(aes) и rfc7539(chacha20,poly1305) в ядре — это те
// же самые конструкции, что crypto/cipher и x/crypto у нас: те же ключи, те же nonce, те же теги.
// Поэтому движок можно менять на ходу и на одной стороне: вторая ничего не заметит. Отсюда и
// граница — ядру отдана только арифметика шифра, а рукопожатие, вывод ключей и вывод nonce остались
// здесь целиком.

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// algName — имя алгоритма в наборе ядра для нашего шифра.
func algName(a AEAD) string {
	if a == AEADAES128 {
		return "gcm(aes)"
	}
	// Имя составное, а не «chacha20poly1305»: короткое имя регистрирует отдельный модуль, а
	// составное собирается шаблоном поверх chacha20 и poly1305 и потому доступно чаще.
	return "rfc7539(chacha20,poly1305)"
}

// algSealer — шифр, который считает ядро.
//
// Держит ДВА дескриптора. Первый (bind) хранит ключ и умеет выдавать рабочие; второй (op) — сама
// операция. Разделение навязано ядром: ключ ставится на первый, а работа идёт на втором, и смена
// ключа означает новый рабочий дескриптор.
//
// ОДИН ЭКЗЕМПЛЯР — ОДНО НАПРАВЛЕНИЕ, и это условие правильности, а не удобство: рабочий дескриптор
// хранит состояние операции, поэтому две горутины, пишущие в него одновременно, получат чужие
// байты. У нас направления и так разведены по разным Keys, но замок здесь всё равно есть — цена
// его ничтожна против операции в десятки микросекунд, а расчёт на дисциплину вызывающего в
// криптографии не стоит ничего.
type algSealer struct {
	mu   sync.Mutex
	bind int
	op   int
	kind AEAD
	tag  int
	// in — буфер под «AAD и открытый текст подряд»: ядро ждёт их одним куском. Свой у каждого
	// направления, поэтому замка ему не нужно сверх того, что выше.
	in []byte
}

const algTagLen = 16

// newAlgSealer поднимает ядерный шифр на этом ключе. Ошибка означает «ядро не умеет» и обрабатывается
// вызывающим как «работаем на Go» — отказом подъёма туннеля она не является никогда.
func newAlgSealer(kind AEAD, key []byte) (*algSealer, error) {
	name := algName(kind)
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("AF_ALG недоступен (%v): нужен CONFIG_CRYPTO_USER_API_AEAD", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrALG{Type: "aead", Name: name}); err != nil {
		unix.Close(fd)
		// ENOENT здесь значит одно из двух, и различить их снаружи важно: либо алгоритма нет в
		// наборе ядра (не тот модуль), либо нет ФРОНТЕНДА algif_aead — а его многие сборки
		// намеренно запрещают в /etc/modprobe.d, потому что он открывает ядерную криптографию всем
		// процессам. Второе выглядит точно так же, как первое, и без подсказки человек будет
		// ставить не те модули.
		hint := ""
		if err == unix.ENOENT {
			if algDrivers(kind) != "" {
				hint = " — алгоритм в /proc/crypto ЕСТЬ, значит запрещён или не собран сам " +
					"algif_aead (проверьте /etc/modprobe.d и CONFIG_CRYPTO_USER_API_AEAD)"
			} else {
				hint = " — этого алгоритма нет в /proc/crypto: нужен свой модуль ядра"
			}
		}
		return nil, fmt.Errorf("ядро не даёт %s (%v)%s", name, err, hint)
	}
	s := &algSealer{bind: fd, op: -1, kind: kind, tag: algTagLen}
	if err := unix.SetsockoptInt(fd, unix.SOL_ALG, unix.ALG_SET_AEAD_AUTHSIZE, algTagLen); err != nil {
		s.Close()
		return nil, fmt.Errorf("%s: тег %d байт не принят: %v", name, algTagLen, err)
	}
	if err := s.setKey(key); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// setKey ставит ключ и заводит новый рабочий дескриптор. Зовётся и при смене эпохи.
func (s *algSealer) setKey(key []byte) error {
	if err := unix.SetsockoptString(s.bind, unix.SOL_ALG, unix.ALG_SET_KEY, string(key)); err != nil {
		return fmt.Errorf("%s: ключ не принят: %v", algName(s.kind), err)
	}
	op, _, err := unix.Accept4(s.bind, unix.SOCK_CLOEXEC)
	if err != nil {
		return fmt.Errorf("%s: рабочий дескриптор не выдан: %v", algName(s.kind), err)
	}
	if s.op >= 0 {
		unix.Close(s.op)
	}
	s.op = op
	return nil
}

func (s *algSealer) overhead() int { return s.tag }
func (s *algSealer) name() string  { return "ядро/" + algName(s.kind) }

func (s *algSealer) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Close()
}

// Close закрывает дескрипторы. Без замка: зовётся из newAlgSealer до выдачи наружу и из close().
func (s *algSealer) Close() {
	if s.op >= 0 {
		unix.Close(s.op)
		s.op = -1
	}
	if s.bind >= 0 {
		unix.Close(s.bind)
		s.bind = -1
	}
}

// seal шифрует. dst обязан иметь ёмкость под len(pt)+tag; результат — dst[:len(pt)+tag].
//
// ЯДРО ЖДЁТ AAD И ТЕКСТ ОДНИМ КУСКОМ и возвращает так же: на выходе сперва те же байты AAD, потом
// шифротекст с тегом. Отсюда копия во внутренний буфер и копия обратно. На той машине, где ядерный
// путь вообще выбирают, эти копии — единицы микросекунд против десятков у самой операции; на той,
// где они значимы, выбран будет Go.
func (s *algSealer) seal(dst, nonce, pt, aad []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	need := len(aad) + len(pt) + s.tag
	if cap(s.in) < need {
		s.in = make([]byte, need)
	}
	buf := s.in[:len(aad)+len(pt)]
	copy(buf, aad)
	copy(buf[len(aad):], pt)
	out := s.in[:need]
	if err := s.run(unix.ALG_OP_ENCRYPT, nonce, len(aad), buf, out); err != nil {
		return nil, err
	}
	if cap(dst) < len(pt)+s.tag {
		return nil, fmt.Errorf("noise: мал буфер под шифротекст")
	}
	dst = dst[:len(pt)+s.tag]
	copy(dst, out[len(aad):])
	return dst, nil
}

// open расшифровывает. Возвращает открытый текст в dst.
func (s *algSealer) open(dst, nonce, ct, aad []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(ct) < s.tag {
		return nil, ErrAuth
	}
	need := len(aad) + len(ct)
	if cap(s.in) < need {
		s.in = make([]byte, need)
	}
	buf := s.in[:need]
	copy(buf, aad)
	copy(buf[len(aad):], ct)
	// На выходе ядро отдаёт AAD и открытый текст — то есть на тег короче входа.
	out := s.in[:need-s.tag]
	if err := s.run(unix.ALG_OP_DECRYPT, nonce, len(aad), buf, out); err != nil {
		// Несошедшийся тег ядро называет EBADMSG. Отделять его обязательно: это чужой или
		// подделанный пакет, его отбрасывают счётчиком и соединение НЕ рвут.
		return nil, ErrAuth
	}
	plen := len(ct) - s.tag
	if cap(dst) < plen {
		return nil, fmt.Errorf("noise: мал буфер под открытый текст")
	}
	dst = dst[:plen]
	copy(dst, out[len(aad):])
	return dst, nil
}

// algCtrl собирает управляющие сообщения одной операции: что делать, каким nonce, сколько байт в
// начале — это AAD.
//
// СОБИРАЕТСЯ РУКАМИ, и это самая рискованная часть файла: выравнивание заголовков, порядок байт
// полей ядра и упаковка af_alg_iv ошибаются молча, а проявляются несошедшимся тегом. Поэтому
// функция отдельная — её раскладку проверяет тест разбором штатным ParseSocketControlMessage, а
// живой вызов с этими же сообщениями проверяется на algif_skcipher (см. alg_linux_test.go).
func algCtrl(op int, iv []byte, assoclen int) []byte {
	ivSpace := unix.CmsgSpace(4 + len(iv))
	ctrl := make([]byte, unix.CmsgSpace(4)+ivSpace+unix.CmsgSpace(4))
	o := 0
	putCmsg := func(typ int, body []byte) {
		h := (*unix.Cmsghdr)(unsafe.Pointer(&ctrl[o]))
		h.Level = unix.SOL_ALG
		h.Type = int32(typ)
		h.SetLen(unix.CmsgLen(len(body)))
		copy(ctrl[o+unix.CmsgLen(0):], body)
		o += unix.CmsgSpace(len(body))
	}
	var b4 [4]byte
	putU32(b4[:], uint32(op))
	putCmsg(unix.ALG_SET_OP, b4[:])
	// af_alg_iv: длина nonce, потом сам nonce.
	ivBody := make([]byte, 4+len(iv))
	putU32(ivBody[:4], uint32(len(iv)))
	copy(ivBody[4:], iv)
	putCmsg(unix.ALG_SET_IV, ivBody)
	putU32(b4[:], uint32(assoclen))
	putCmsg(unix.ALG_SET_AEAD_ASSOCLEN, b4[:])
	return ctrl
}

// run — одна операция: sendmsg с настройками в управляющих сообщениях, потом чтение результата.
func (s *algSealer) run(op int, iv []byte, assoclen int, in, out []byte) error {
	ctrl := algCtrl(op, iv, assoclen)
	if err := sendmsgAlg(s.op, in, ctrl); err != nil {
		return err
	}
	got := 0
	for got < len(out) {
		n, err := unix.Read(s.op, out[got:])
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return fmt.Errorf("AF_ALG вернул %d байт из %d", got, len(out))
		}
		got += n
	}
	return nil
}

func putU32(b []byte, v uint32) {
	// Порядок МАШИННЫЙ: это поля структур ядра, а не байты провода.
	if isLittleEndian {
		b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
		return
	}
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}

var isLittleEndian = func() bool {
	var x uint16 = 1
	return *(*byte)(unsafe.Pointer(&x)) == 1
}()

// sendmsgAlg — sendmsg с управляющими сообщениями и одним куском данных.
func sendmsgAlg(fd int, data, ctrl []byte) error {
	for {
		err := unix.Sendmsg(fd, data, ctrl, nil, 0)
		if err == unix.EINTR {
			continue
		}
		return err
	}
}

// algProbe — умеет ли ядро наш шифр. Отдельно от newAlgSealer, чтобы проверять до выбора движка и
// не тратить ключ.
func algProbe(kind AEAD) error {
	// Ключ нулевой и нужной длины: проверяется доступность алгоритма, а не сама криптография.
	key := make([]byte, 32)
	if kind == AEADAES128 {
		key = key[:16]
	}
	s, err := newAlgSealer(kind, key)
	if err != nil {
		return err
	}
	s.Close()
	return nil
}

// algDrivers — какой драйвер ядра стоит за нашим шифром, по /proc/crypto.
//
// Только для строки в журнале, и строка эта нужнее, чем кажется: «ядерная криптография включена»
// само по себе не говорит ничего, а имя драйвера говорит всё. gcm(aes-eip93) означает, что считает
// микросхема; gcm_base(ctr(aes-generic),ghash-generic) — что тот же процессор, только через два
// системных вызова.
//
// Разбор по БЛОКАМ, а не построчно: /proc/crypto перечисляет алгоритмы блоками, разделёнными пустой
// строкой, и одно имя встречается в нескольких блоках с разными приоритетами. Ищем блок с нужным
// именем и типом aead, а среди подходящих — с наибольшим приоритетом: именно его и выберет ядро.
func algDrivers(kind AEAD) string {
	body, err := os.ReadFile("/proc/crypto")
	if err != nil {
		return ""
	}
	want := algName(kind)
	best, bestPrio := "", -1
	var name, driver, typ string
	prio := 0
	flush := func() {
		if name == want && typ == "aead" && prio > bestPrio {
			best, bestPrio = driver, prio
		}
		name, driver, typ, prio = "", "", "", 0
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "name":
			name = v
		case "driver":
			driver = v
		case "type":
			typ = v
		case "priority":
			fmt.Sscanf(v, "%d", &prio)
		}
	}
	flush()
	return best
}

// ---- когда ядру можно доверять шифр ------------------------------------------

// algLoaded — доступен ли фронтенд algif_aead БЕЗ его загрузки.
//
// ЗАЧЕМ ЭТА ПРОВЕРКА СУЩЕСТВУЕТ, И ПОЧЕМУ ОНА НЕ ПЕДАНТИЗМ. Привязка сокета AF_ALG к алгоритму
// заставляет ядро подгрузить algif_aead само, по требованию. То есть один наш замер на машине, где
// этого модуля не было, ЗАГРУЖАЕТ его — и оставляет загруженным. А у algif_aead есть своя история:
// на этой самой машине сборки он выключен явным `install algif_aead /bin/false` из-за
// CVE-2026-31431 (copy.fail), и такой запрет — обычное дело в защищённых сборках, потому что
// фронтенд открывает ядерную криптографию любому процессу.
//
// Поэтому режим «авто» ядро НЕ ПРОБУЕТ, пока фронтенд не доступен и так: молча расширять
// поверхность атаки машины ради процентов скорости нельзя. Явное `--crypto kernel` пробует — там
// человек решил сам, и это его право.
func algLoaded() bool {
	// Каталог есть и у загруженного модуля, и у встроенного в ядро: /sys/module заводится на оба.
	if _, err := os.Stat("/sys/module/algif_aead"); err == nil {
		return true
	}
	return false
}

// algSelfTest сверяет ядерный шифр с эталоном — своим же кодом — и возвращает ошибку при любом
// расхождении.
//
// ЭТО НЕ ПЕРЕСТРАХОВКА, А УСЛОВИЕ ВОЗМОЖНОСТИ. Проверить AF_ALG на всех сочетаниях ядра, драйвера и
// железа нельзя: на машине сборки фронтенд запрещён, на роутере не собран, а работать код будет
// там, где мы его не видели. Значит проверять обязан он сам — на той машине, где его выбирают, и
// ДО того, как через него пойдёт трафик. Расхождение в один байт означало бы туннель, который
// поднимается и не несёт данные, причём в одну сторону; поймать это иначе можно только живым
// прогоном на каждом сочетании.
//
// Проверяется три свойства, и все три обязательны: шифротекст совпадает с эталонным до байта,
// расшифровка возвращает исходный текст, испорченный тег ОТВЕРГАЕТСЯ. Третье — потому что молча
// принимающий подделку AEAD хуже отсутствующего.
func algSelfTest(kind AEAD) error {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*13 + 1)
	}
	k := key
	if kind == AEADAES128 {
		k = key[:16]
	}
	ker, err := newAlgSealer(kind, k)
	if err != nil {
		return err
	}
	defer ker.Close()
	ref, err := newGoSealer(kind, k)
	if err != nil {
		return err
	}
	// Длины выбраны так, чтобы задеть все особые случаи: пустая запись (keepalive), нечётная,
	// полноразмерный пакет и предельная запись с пачкой кадров.
	for _, n := range []int{0, 1, 37, 1440, 8176} {
		pt := make([]byte, n)
		for i := range pt {
			pt[i] = byte(i*31 + 7)
		}
		aad := []byte{0x17, 0x03, 0x03, byte(n >> 8), byte(n)}
		nonce := make([]byte, 12)
		for i := range nonce {
			nonce[i] = byte(n + i)
		}
		want, err := ref.seal(make([]byte, 0, n+16), nonce, pt, aad)
		if err != nil {
			return err
		}
		got, err := ker.seal(make([]byte, 0, n+16), nonce, pt, aad)
		if err != nil {
			return fmt.Errorf("длина %d: ядро не зашифровало: %v", n, err)
		}
		if len(got) != len(want) {
			return fmt.Errorf("длина %d: ядро дало %d байт вместо %d", n, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				return fmt.Errorf("длина %d: ядро дало ДРУГОЙ шифротекст (первое расхождение в "+
					"байте %d) — тот же алгоритм обязан давать те же байты", n, i)
			}
		}
		// Расшифровка своего же шифротекста.
		back, err := ker.open(make([]byte, 0, n), nonce, got, aad)
		if err != nil {
			return fmt.Errorf("длина %d: ядро не расшифровало то, что само зашифровало: %v", n, err)
		}
		if len(back) != n {
			return fmt.Errorf("длина %d: расшифровка дала %d байт", n, len(back))
		}
		for i := range pt {
			if back[i] != pt[i] {
				return fmt.Errorf("длина %d: расшифровка дала другой текст (байт %d)", n, i)
			}
		}
		// Испорченный тег обязан быть отвергнут.
		bad := make([]byte, len(got))
		copy(bad, got)
		bad[len(bad)-1] ^= 0x80
		if _, err := ker.open(make([]byte, 0, n), nonce, bad, aad); err == nil {
			return fmt.Errorf("длина %d: ядро ПРИНЯЛО запись с испорченным тегом — такой AEAD "+
				"хуже отсутствующего", n)
		}
	}
	return nil
}
