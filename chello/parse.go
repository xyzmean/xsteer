package chello

import "errors"

// Ref — где внутри ClientHello лежат поля, которые несут рукопожатие xsteer.
//
// Смещения даются ОТ НАЧАЛА ЗАПИСИ (то есть от байта 0x16), потому что именно запись приходит из
// сокета и именно по ней считается подписываемая часть. Ноль в поле смещения означает «этого в
// Hello нет».
//
// Смещения, а не срезы: подписываемая часть считается по тем же байтам, что пришли, и вызывающему
// нужно знать не только «где ключ», но и «на каком месте его обнулить», чтобы восстановить
// подписанные байты. Со срезами это выражается хуже.
type Ref struct {
	HSOff, HSLen   int // сообщение рукопожатия внутри записи: по нему считается подпись
	SIDOff         int // legacy_session_id, ровно 32 байта
	KSOff          int // публичный ключ x25519 в key_share, ровно 32 байта
	ECHOff, ECHLen int // набивка ECH: где и сколько
	// Suite — первый набор шифров TLS 1.3 из списка клиента, GREASE пропущен. Через него
	// согласуется AEAD: выбор делает клиент, потому что узкое место — его процессор, а не
	// сервер.
	Suite uint16
	SNI   string
}

// ErrNotHello — это не ClientHello или он битый. Одна ошибка на все случаи НАМЕРЕННО: разбирать,
// чем именно плох чужой пакет, значит рассказывать об этом тому, кто его прислал. На публичном
// порту хаба такой разговор не нужен.
var ErrNotHello = errors.New("chello: не ClientHello или битый")

// cur — курсор с проверкой границ на каждом шаге. Заведён потому, что альтернатива — считать
// длины вручную в двух десятках мест, и ровно там появляется чтение за буфером.
type cur struct {
	p []byte
	i int
}

func (c *cur) need(k int) bool { return c.i+k <= len(c.p) }
func (c *cur) u8() (int, bool) {
	if !c.need(1) {
		return 0, false
	}
	v := int(c.p[c.i])
	c.i++
	return v, true
}
func (c *cur) u16() (int, bool) {
	if !c.need(2) {
		return 0, false
	}
	v := int(c.p[c.i])<<8 | int(c.p[c.i+1])
	c.i += 2
	return v, true
}
func (c *cur) u24() (int, bool) {
	if !c.need(3) {
		return 0, false
	}
	v := int(c.p[c.i])<<16 | int(c.p[c.i+1])<<8 | int(c.p[c.i+2])
	c.i += 3
	return v, true
}
func (c *cur) skip(k int) bool {
	if !c.need(k) {
		return false
	}
	c.i += k
	return true
}

// Parse разбирает запись с ClientHello.
//
// ЗАЧЕМ РАЗБОР ВООБЩЕ НУЖЕН КЛИЕНТУ, а не только хабу: собранный Hello разбирается тут же, своим
// же разбором, чтобы взять из него границы подписываемой части. Так смещения не считаются дважды
// (в сборке и в проверке) — а два независимых подсчёта одного смещения однажды разъезжаются, и
// проявляется это как «тег не сошёлся» без всякого намёка на причину.
func Parse(rec []byte) (*Ref, error) {
	out := &Ref{}
	c := &cur{p: rec}

	// Запись рукопожатия. Версию записи не проверяем строго: настоящие клиенты ставят и 0x0301,
	// и 0x0303, и это ничего не значит.
	if v, ok := c.u8(); !ok || v != 0x16 {
		return nil, ErrNotHello
	}
	if !c.skip(2) {
		return nil, ErrNotHello
	}
	v, ok := c.u16()
	if !ok {
		return nil, ErrNotHello
	}
	// Запись обязана быть ЦЕЛОЙ и ровно такой, как заявлено: Hello в этом протоколе приходит
	// одним сегментом, поэтому «не хватает конца» здесь означает не поток, а брак.
	if 5+v != len(rec) {
		return nil, ErrNotHello
	}

	out.HSOff = c.i
	if v, ok := c.u8(); !ok || v != 0x01 {
		return nil, ErrNotHello
	}
	n, ok := c.u24()
	if !ok || c.i+n != len(rec) {
		return nil, ErrNotHello
	}
	out.HSLen = 4 + n

	if !c.skip(2) || !c.skip(32) { // legacy_version, random
		return nil, ErrNotHello
	}
	// legacy_session_id: ровно 32 байта — именно столько занимает аутентификатор и именно
	// столько кладёт всякий современный клиент. Другая длина — не наш собеседник.
	if v, ok := c.u8(); !ok || v != 32 {
		return nil, ErrNotHello
	}
	out.SIDOff = c.i
	if !c.skip(32) {
		return nil, ErrNotHello
	}

	sl, ok := c.u16() // cipher_suites
	if !ok || sl == 0 || sl&1 != 0 || !c.need(sl) {
		return nil, ErrNotHello
	}
	end := c.i + sl
	for c.i < end {
		s, ok := c.u16()
		if !ok {
			return nil, ErrNotHello
		}
		if out.Suite != 0 || IsGrease(uint16(s)) {
			continue // уже нашли или это GREASE — но список надо пройти до конца
		}
		// Наборы TLS 1.3: 0x1301..0x1305. Всё остальное (в том числе наборы 1.2, которые
		// браузер тоже перечисляет) нас не касается — согласуется только AEAD.
		if s >= 0x1301 && s <= 0x1305 {
			out.Suite = uint16(s)
		}
	}

	cl, ok := c.u8() // legacy_compression_methods
	if !ok || !c.skip(cl) {
		return nil, ErrNotHello
	}
	el, ok := c.u16()
	if !ok || !c.need(el) {
		return nil, ErrNotHello
	}
	extEnd := c.i + el

	for c.i < extEnd {
		typ, ok1 := c.u16()
		ln, ok2 := c.u16()
		if !ok1 || !ok2 || !c.need(ln) || c.i+ln > extEnd {
			return nil, ErrNotHello
		}
		body := c.i
		switch {
		case typ == 0x0000 && ln >= 5: // server_name
			e := &cur{p: rec[:body+ln], i: body}
			if _, ok := e.u16(); ok {
				if nt, ok := e.u8(); ok && nt == 0 {
					if nl, ok := e.u16(); ok && nl < 128 && e.need(nl) {
						out.SNI = string(rec[e.i : e.i+nl])
					}
				}
			}
		case typ == 0x0033 && ln >= 6: // key_share
			e := &cur{p: rec[:body+ln], i: body}
			sh, ok := e.u16()
			if !ok || body+2+sh > body+ln {
				return nil, ErrNotHello
			}
			shEnd := e.i + sh
			for e.i < shEnd {
				grp, ok1 := e.u16()
				kl, ok2 := e.u16()
				if !ok1 || !ok2 || !e.need(kl) {
					return nil, ErrNotHello
				}
				// GREASE-группа лежит в key_share первой и несёт один случайный байт — взять её
				// за ключ значило бы не найти настоящий вовсе.
				if grp == GroupX25519 && kl == 32 && out.KSOff == 0 {
					out.KSOff = e.i
				}
				e.i += kl
			}
		case typ == ExtECH:
			// Раскладка фальшивого ECH ровно та, что собирает Build: тип(1), kdf(2), aead(2),
			// номер конфигурации(1), длина enc(2) и enc, длина payload(2) и payload. Нам нужен
			// payload — в нём едет запечатанный статический ключ.
			e := &cur{p: rec[:body+ln], i: body}
			_, o1 := e.u8()
			_, o2 := e.u16()
			_, o3 := e.u16()
			_, o4 := e.u8()
			encLen, o5 := e.u16()
			if o1 && o2 && o3 && o4 && o5 && e.skip(encLen) {
				if payLen, ok := e.u16(); ok && e.need(payLen) {
					out.ECHOff, out.ECHLen = e.i, payLen
				}
			}
		}
		c.i = body + ln
	}
	if c.i != extEnd {
		return nil, ErrNotHello
	}
	// Без ключа обмена разговаривать не о чем: это либо не TLS 1.3, либо не наш клиент.
	if out.KSOff == 0 {
		return nil, ErrNotHello
	}
	return out, nil
}
