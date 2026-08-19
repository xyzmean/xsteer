// Рукопожатие целиком в памяти: то же, что делает tests/xsloop.c для реализации на C. Здесь
// проверяется не «функция вернула ноль», а то, ради чего рукопожатие существует: обе стороны
// получили ОДНИ ключи, каждая узнала другую, и подделка на любом шаге не проходит.
package noise

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/xyzmean/xsteer/wire"
)

type seeded struct{ r *rand.Rand }

func (s seeded) Read(p []byte) (int, error) { return s.r.Read(p) }

func keypair(t *testing.T, seed int64) (priv, pub [32]byte) {
	t.Helper()
	r := rand.New(rand.NewSource(seed))
	r.Read(priv[:])
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pub[:], p)
	return
}

// runHandshake проводит полный круг и возвращает обе стороны.
func runHandshake(t *testing.T, aes bool, mtuC, mtuH, connID int) (
	cli, hub *HS, cliTX, cliRX, hubTX, hubRX *Keys) {
	t.Helper()
	cPriv, cPub := keypair(t, 1)
	hPriv, hPub := keypair(t, 2)

	cli, hub = &HS{}, &HS{}
	hello, err := cli.ClientHello(cPriv, hPub, "www.microsoft.com", mtuC, connID, aes, true,
		seeded{rand.New(rand.NewSource(11))})
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if err := hub.ServerRead(hPriv, hello, seeded{rand.New(rand.NewSource(22))}); err != nil {
		t.Fatalf("ServerRead: %v", err)
	}
	if hub.PeerStatic != cPub {
		t.Fatal("хаб узнал не того пира — статический ключ из msg1 расшифрован неверно")
	}
	if hub.Peer.ConnID() != connID {
		t.Errorf("номер соединения приехал как %d, а не %d", hub.Peer.ConnID(), connID)
	}
	if int(hub.Peer.MTU) != mtuC {
		t.Errorf("MTU клиента приехал как %d, а не %d", hub.Peer.MTU, mtuC)
	}
	resp, hubTX, hubRX, err := hub.ServerWrite(mtuH)
	if err != nil {
		t.Fatalf("ServerWrite: %v", err)
	}
	cliTX, cliRX, consumed, err := cli.ClientFinish(resp)
	if err != nil {
		t.Fatalf("ClientFinish: %v", err)
	}
	if consumed != len(resp) {
		t.Errorf("клиент израсходовал %d из %d байт ответа", consumed, len(resp))
	}
	if int(cli.Peer.MTU) != mtuH {
		t.Errorf("MTU хаба приехал как %d, а не %d", cli.Peer.MTU, mtuH)
	}
	conf, err := cli.ClientConfirm(cliTX)
	if err != nil {
		t.Fatalf("ClientConfirm: %v", err)
	}
	if n, err := hub.ServerConfirm(hubRX, conf); err != nil || n != len(conf) {
		t.Fatalf("ServerConfirm: %v (израсходовано %d из %d)", err, n, len(conf))
	}
	return
}

// ResponseComplete обязан узнавать конец ответа по одной рамке записей и НЕ раньше времени: на
// этом держится право звать ClientFinish ровно один раз. Проверяем на настоящем ответе хаба, что на
// каждом неполном префиксе он молчит, а на полном ответе (и с лишними данными за ним) говорит «да».
func TestResponseComplete(t *testing.T) {
	cPriv, _ := keypair(t, 1)
	hPriv, hPub := keypair(t, 2)
	cli, hub := &HS{}, &HS{}
	hello, err := cli.ClientHello(cPriv, hPub, "www.microsoft.com", 1439, 0, true, true,
		seeded{rand.New(rand.NewSource(11))})
	if err != nil {
		t.Fatalf("ClientHello: %v", err)
	}
	if err := hub.ServerRead(hPriv, hello, seeded{rand.New(rand.NewSource(22))}); err != nil {
		t.Fatalf("ServerRead: %v", err)
	}
	resp, _, _, err := hub.ServerWrite(1439)
	if err != nil {
		t.Fatalf("ServerWrite: %v", err)
	}

	// Каждый префикс короче полного — незакончен.
	for i := 0; i < len(resp); i++ {
		if ResponseComplete(resp[:i]) {
			t.Fatalf("ResponseComplete сказал «готово» на %d из %d байт", i, len(resp))
		}
	}
	// Полный ответ — готов.
	if !ResponseComplete(resp) {
		t.Fatal("ResponseComplete не узнал полный ответ")
	}
	// С данными вплотную за подтверждением — тоже готов (граница определяется рамкой записи-fin, а
	// не концом буфера): именно так ответ и приходит по потоку, где следом уже едут записи данных.
	withData := append(append([]byte{}, resp...), 0x17, 0x03, 0x03, 0x00, 0x30)
	if !ResponseComplete(withData) {
		t.Fatal("ResponseComplete не узнал ответ, за которым уже идут данные")
	}

	// И самое главное: разбор один раз на полном ответе сходится (тот же путь, что в обоих
	// транспортах после ResponseComplete).
	if _, _, _, err := cli.ClientFinish(resp); err != nil {
		t.Fatalf("ClientFinish на полном ответе: %v", err)
	}
}

func TestРукопожатиеЦеликом(t *testing.T) {
	for _, aes := range []bool{true, false} {
		name := "ChaCha20-Poly1305"
		if aes {
			name = "AES-128-GCM"
		}
		t.Run(name, func(t *testing.T) {
			cli, hub, cliTX, cliRX, hubTX, hubRX := runHandshake(t, aes, 1439, 1387, 3)
			if cli.h != hub.h {
				t.Fatal("транскрипты сторон разошлись")
			}
			if cliTX.Kind() != hubRX.Kind() {
				t.Error("стороны согласовали разные шифры")
			}
			// Направления обязаны сойтись: то, что зашифровал клиент, читает хаб, и наоборот.
			// Ошибка здесь даёт «туннель поднялся и молчит» — самый дорогой в отладке случай.
			for _, dir := range []struct {
				name   string
				tx, rx *Keys
			}{{"клиент → хаб", cliTX, hubRX}, {"хаб → клиент", hubTX, cliRX}} {
				pt := []byte("сорок пять байт данных внутри туннеля, ага")
				buf := make([]byte, len(pt)+wire.Tag)
				copy(buf, pt)
				var hdr [wire.RecHdr]byte
				if err := wire.RecBuild(hdr[:], len(pt)+wire.Tag); err != nil {
					t.Fatal(err)
				}
				if _, err := dir.tx.Seal(buf, len(pt), hdr[:], 7); err != nil {
					t.Fatal(err)
				}
				got, err := dir.rx.Open(buf, hdr[:], 7)
				if err != nil {
					t.Fatalf("%s: запись не расшифровалась: %v", dir.name, err)
				}
				if !bytes.Equal(got, pt) {
					t.Errorf("%s: данные испортились", dir.name)
				}
			}
			// Смещение (номер записи) входит в nonce: та же запись под другим смещением обязана не
			// расшифровываться. Без этого повтор пакета проходил бы незамеченным.
			pt := []byte("keepalive")
			buf := make([]byte, len(pt)+wire.Tag)
			copy(buf, pt)
			var hdr [wire.RecHdr]byte
			_ = wire.RecBuild(hdr[:], len(pt)+wire.Tag)
			if _, err := cliTX.Seal(buf, len(pt), hdr[:], 5); err != nil {
				t.Fatal(err)
			}
			if _, err := hubRX.Open(append([]byte(nil), buf...), hdr[:], 6); err == nil {
				t.Error("запись расшифровалась под чужим смещением — nonce не связан со смещением")
			}
			// Заголовок записи — это AAD: подмена заявленной длины обязана ломать тег.
			bad := [wire.RecHdr]byte{}
			copy(bad[:], hdr[:])
			bad[4] ^= 1
			if _, err := hubRX.Open(append([]byte(nil), buf...), bad[:], 5); err == nil {
				t.Error("подменённый заголовок записи не сломал тег — значит он не входит в AAD")
			}
		})
	}
}

func TestNonceСовпадаетСПроводом(t *testing.T) {
	// wire.Nonce и вывод nonce внутри шифра — два подсчёта одного и того же. Разойдись они,
	// туннель молча не расшифровывался бы ни одного пакета.
	var iv [12]byte
	for i := range iv {
		iv[i] = byte(i * 7)
	}
	k := &Keys{iv: iv}
	for _, rel := range []uint32{1, 2, 255, 256, 65535, 1 << 20, 0xFFFFFFFF} {
		if k.nonce(uint64(rel)) != wire.Nonce(iv, rel) {
			t.Fatalf("nonce разошёлся со проводом на смещении %d", rel)
		}
	}
}

func TestЦепочкаNoiseЭтоHKDF(t *testing.T) {
	// Утверждение, на котором стоит отказ от своего HMAC: HKDF-Expand(prk, "", 64) даёт
	// T1 || T2, где T1 = HMAC(prk, 0x01) и T2 = HMAC(prk, T1 || 0x02) — буква в букву цепочка
	// Noise. «Должно совпадать» и «совпадает» — разные утверждения, поэтому здесь независимый
	// подсчёт.
	ck := sha256.Sum256([]byte("цепочка"))
	ikm := sha256.Sum256([]byte("общий секрет"))
	prk := hkdf.Extract(sha256.New, ikm[:], ck[:])

	var out [64]byte
	if _, err := io.ReadFull(hkdf.Expand(sha256.New, prk, nil), out[:]); err != nil {
		t.Fatal(err)
	}

	m := hmac.New(sha256.New, prk)
	m.Write([]byte{0x01})
	t1 := m.Sum(nil)
	m.Reset()
	m.Write(t1)
	m.Write([]byte{0x02})
	t2 := m.Sum(nil)

	if !bytes.Equal(out[:32], t1) || !bytes.Equal(out[32:], t2) {
		t.Fatal("HKDF и цепочка HMAC разошлись — тогда своё расписание Noise писать пришлось бы вручную")
	}
}

func TestПодделкиНеПроходят(t *testing.T) {
	cPriv, _ := keypair(t, 1)
	hPriv, hPub := keypair(t, 2)
	_, otherPub := keypair(t, 3)

	// Hello, адресованный ДРУГОМУ хабу, не сходится у этого: статический ключ отвечающего входит
	// в транскрипт как предварительное сообщение, и это то, что связывает рукопожатие с
	// конкретным хабом.
	cli := &HS{}
	hello, err := cli.ClientHello(cPriv, otherPub, "x", 1439, 0, true, true, seeded{rand.New(rand.NewSource(5))})
	if err != nil {
		t.Fatal(err)
	}
	hub := &HS{}
	if err := hub.ServerRead(hPriv, hello, nil); err == nil {
		t.Error("хаб принял Hello, адресованный другому хабу")
	} else if !errors.Is(err, ErrAuth) {
		t.Errorf("отказ обязан быть про аутентификацию, а вышел %v", err)
	}

	// Честный Hello с испорченным байтом: каждый байт по очереди. Ни один не должен привести к
	// принятию, и ни один — к панике: сюда приходит что угодно из интернета.
	cli2 := &HS{}
	good, err := cli2.ClientHello(cPriv, hPub, "www.microsoft.com", 1439, 0, true, true,
		seeded{rand.New(rand.NewSource(6))})
	if err != nil {
		t.Fatal(err)
	}
	if err := (&HS{}).ServerRead(hPriv, good, nil); err != nil {
		t.Fatalf("честный Hello отвергнут: %v", err)
	}
	accepted := 0
	for i := 0; i < len(good); i++ {
		// Байты 1 и 2 — версия ЗАПИСИ, и они не покрыты ни проверкой, ни тегом НАМЕРЕННО.
		// Подписывается сообщение рукопожатия, а не запись: настоящие клиенты ставят там и
		// 0x0301, и 0x0303, посредники это поле нормализуют, и требовать от него точности
		// значило бы рвать рукопожатие из-за байта, который ничего не решает. Реализация на C
		// ведёт себя так же, и менять это здесь нельзя — расхождение стоило бы совместимости.
		if i == 1 || i == 2 {
			continue
		}
		bad := append([]byte(nil), good...)
		bad[i] ^= 0x80
		if err := (&HS{}).ServerRead(hPriv, bad, nil); err == nil {
			accepted++
			t.Errorf("испорченный байт %d принят", i)
		}
	}
	if accepted != 0 {
		t.Errorf("принято испорченных Hello: %d", accepted)
	}

	// Подтверждение, подписанное чужим ключом, не проходит: иначе записанный msg1 давал бы сессию.
	cli3, hub3, cliTX, _, _, hubRX := runHandshake(t, true, 1439, 1439, 0)
	_ = cli3
	_ = hub3
	conf, err := cli3.ClientConfirm(cliTX)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), conf...)
	bad[wire.RecHdr+3] ^= 1
	if _, err := hub3.ServerConfirm(hubRX, bad); err == nil {
		t.Error("подделанное подтверждение принято")
	}
}

func TestОтветНеБайтОдинаковый(t *testing.T) {
	// Длина «сертификата» случайная: постоянная сама стала бы отпечатком. Проверяем, что она
	// действительно разная и лежит в разумных пределах — весь ответ обязан влезть в один сегмент.
	seen := map[int]bool{}
	for i := 0; i < 12; i++ {
		_, _, _, _, _, _ = runHandshake(t, true, 1439, 1439, 0)
	}
	cPriv, _ := keypair(t, 1)
	hPriv, hPub := keypair(t, 2)
	for i := 0; i < 12; i++ {
		cli := &HS{}
		hello, err := cli.ClientHello(cPriv, hPub, "www.microsoft.com", 1439, 0, true, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		hub := &HS{}
		if err := hub.ServerRead(hPriv, hello, nil); err != nil {
			t.Fatal(err)
		}
		resp, _, _, err := hub.ServerWrite(1439)
		if err != nil {
			t.Fatal(err)
		}
		if len(resp) > 1400 {
			t.Fatalf("ответ хаба %d байт — он обязан влезать в один сегмент", len(resp))
		}
		seen[len(resp)] = true
	}
	if len(seen) < 5 {
		t.Errorf("длина ответа приняла всего %d разных значений из 12 попыток — постоянная длина это отпечаток", len(seen))
	}
}

func TestОтказНеузнанному(t *testing.T) {
	a := Alert()
	want := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}
	if !bytes.Equal(a, want) {
		t.Errorf("отказ должен выглядеть как fatal handshake_failure настоящего TLS: % x", a)
	}
}
