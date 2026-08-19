package hub

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"time"

	"github.com/xyzmean/xsteer/conf"
	"github.com/xyzmean/xsteer/link"
	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/route"
	"github.com/xyzmean/xsteer/wire"
)

// rxLoop — приём от пиров и обслуживание своих сессий.
//
// Обслуживание идёт ЗДЕСЬ ЖЕ, а не в отдельной горутине, и это не экономия: таблица сессий
// принадлежит этому воркеру, и трогать её из второй горутины значило бы завести замок на пути,
// который и так под потоком.
func (w *worker) rxLoop(ctx context.Context) {
	buf := make([]byte, wire.Row)
	last := time.Now()
	for ctx.Err() == nil {
		ok, err := w.rx.WaitRead(50 * time.Millisecond)
		if err != nil {
			return
		}
		if ok {
			// Читаем, пока есть что: одно событие готовности обычно означает целую пачку.
			for i := 0; i < 64; i++ {
				n, err := w.rx.Recv(buf)
				if err != nil {
					break
				}
				seg, ok := link.ParseSeg(buf[:n])
				if !ok || seg.DPort != uint16(w.h.opt.Conf.ListenPort) {
					continue
				}
				w.onSeg(&seg)
			}
		}
		if time.Since(last) >= 100*time.Millisecond {
			w.maintain()
			last = time.Now()
		}
	}
}

func (w *worker) onSeg(seg *link.Seg) {
	k := skey{addr: seg.SAddr, port: seg.SPort}
	s := w.sess[k]

	// SYN без ACK — начало соединения либо его повтор.
	if seg.Flags&link.SYN != 0 && seg.Flags&link.ACK == 0 {
		if s != nil {
			_ = s.conn.OnSynAgain(seg)
			return
		}
		w.accept(k, seg)
		return
	}
	if s == nil {
		// Данные по сессии, которой нет: пир пережил наш перезапуск. RST говорит ему об этом
		// сразу — иначе он узнает по тишине, то есть через сорок пять секунд простоя туннеля.
		// Окно 65535, а не ноль: именно этим наш RST отличается от RST ядра, который гасит правило.
		w.sendRST(seg)
		return
	}
	data, err := s.conn.OnSeg(seg)
	if err != nil {
		w.free(k, s)
		return
	}
	if !data {
		return
	}
	switch s.phase {
	case phSyn:
		w.handshake(k, s, seg)
	case phHS:
		w.confirm(k, s, seg)
	case phEst:
		w.onData(s, seg)
	case phProxy:
		// Не наш: байты идут настоящему серверу как есть.
		w.proxyUp(k, s, seg)
	}
}

// accept — новая сессия на первом же поддельном SYN.
//
// Сессия создаётся БЕЗ всякой проверки: кто угодно из интернета может прислать SYN. Отсюда правило
// вытеснения в evict — неподтверждённые уходят первыми, иначе поток SYN с меняющихся портов выбивал
// бы из таблицы живые туннели, то есть стоил бы отказа в обслуживании ценой одного цикла на
// постороннем хосте.
func (w *worker) accept(k skey, seg *link.Seg) {
	if len(w.sess) >= SessPerWorker {
		if !w.evict() {
			return
		}
	}
	raw, err := link.OpenRawSend(seg.SAddr)
	if err != nil {
		return
	}
	var isnBuf [4]byte
	if _, err := rand.Read(isnBuf[:]); err != nil {
		raw.Close()
		return
	}
	conn, err := link.Accept(raw, seg, uint16(w.h.opt.Conf.ListenPort),
		binary.BigEndian.Uint32(isnBuf[:]))
	if err != nil {
		raw.Close()
		return
	}
	bm := 2
	if w.h.opt.NoBatch {
		bm = 1
	}
	w.sess[k] = &session{conn: conn, phase: phSyn, peer: -1, connID: -1, batchMax: bm}
}

// evict освобождает место: сперва самую давнюю НЕподтверждённую, и только если таких нет — самую
// давнюю вообще. Подтверждённую сессию у нас может забрать только другая подтверждённая.
func (w *worker) evict() bool {
	var victim *session
	var vk skey
	var raw *session
	var rk skey
	for k, s := range w.sess {
		if s.phase != phEst {
			if raw == nil || s.conn.Idle() > raw.conn.Idle() {
				raw, rk = s, k
			}
		}
		if victim == nil || s.conn.Idle() > victim.conn.Idle() {
			victim, vk = s, k
		}
	}
	if raw != nil {
		w.free(rk, raw)
		return true
	}
	if victim != nil {
		w.free(vk, victim)
		return true
	}
	return false
}

func (w *worker) free(k skey, s *session) {
	// Замок берётся ДО обнуления: в этот самый миг другой воркер может быть внутри отправки в эту
	// сессию (пир↔пир или пакет из TUN). Проверку «сессия ещё жива» отправка делает под этим же
	// замком, поэтому после освобождения она просто ничего не отправит.
	s.mu.Lock()
	s.phase = phFree
	if s.hs != nil {
		s.hs.Wipe()
		s.hs = nil
	}
	s.tx, s.rx = nil, nil
	s.conn.Close()
	s.mu.Unlock()
	if s.peer >= 0 && s.connID >= 0 {
		w.h.peerSess[s.peer][s.connID].CompareAndSwap(s, nil)
	}
	delete(w.sess, k)
}

// handshake — разобрать Hello пира и ответить.
//
// СОБИРАЕМ ИЗ СЕГМЕНТОВ. Браузерный ClientHello больше одного сегмента (у современного Chrome он
// около 1700 байт из-за постквантового ключа), и наш такой же — иначе размер Hello сам по себе
// признак. Значит первый сегмент почти всегда неполон, и разбирать его сразу нельзя.
//
// Предел на накопленное обязателен: сюда пишет кто угодно из интернета, и «копим, пока не
// разберётся» без предела — это способ съесть память хаба чужими байтами.
func (w *worker) handshake(k skey, s *session, seg *link.Seg) {
	const helloMax = 4096
	if len(s.hsBuf)+len(seg.Payload) > helloMax {
		w.h.stats.strangers.Add(1)
		w.onStranger(k, s, seg, nil)
		return
	}
	s.hsBuf = append(s.hsBuf, seg.Payload...)
	// НЕ ПОХОЖЕ НА РУКОПОЖАТИЕ TLS ВООБЩЕ — отвечаем сразу, не ожидая продолжения.
	//
	// Это про зондирование, а не про аккуратность. Прибор первым делом пробует не только настоящий
	// ClientHello: он присылает и «GET / HTTP/1.1», и просто мусор. Пока проверки не было, такие
	// байты копились до предела в надежде, что придёт заявленная длина, — то есть открытый порт
	// молчал в ответ на запрос HTTP, чего настоящий сервер не делает никогда. Молчание в ответ на
	// мусор отличимо не хуже, чем молчание в ответ на Hello.
	if len(s.hsBuf) >= 2 && (s.hsBuf[0] != 0x16 || s.hsBuf[1] != 0x03) {
		w.h.stats.strangers.Add(1)
		w.onStranger(k, s, seg, nil)
		return
	}
	// Ждём, пока запись рукопожатия придёт целиком: длина её заявлена в первых пяти байтах.
	if len(s.hsBuf) < 5 {
		return
	}
	if want := 5 + int(s.hsBuf[3])<<8 + int(s.hsBuf[4]); len(s.hsBuf) < want {
		return
	}
	full := s.hsBuf
	s.hsBuf = nil
	hs := &noise.HS{}
	if err := hs.ServerRead(w.h.opt.Sec.Priv, full, nil); err != nil {
		w.h.stats.strangers.Add(1)
		w.onStranger(k, s, seg, err)
		return
	}
	// Личность известна — ищем пира. Линейный обход: раз на рукопожатие.
	found := -1
	for i := range w.h.opt.Conf.Peers {
		if w.h.opt.Conf.Peers[i].Pub == hs.PeerStatic {
			found = i
			break
		}
	}
	if found < 0 {
		// Сюда попадает ЛЮБОЙ, кто сделал себе пару ключей: статический ключ инициатора
		// подтверждается общим секретом с нашим, а он считается из нашего ОТКРЫТОГО ключа. То есть
		// частоту этой строки выбирает посторонний — отсюда ограничитель.
		if ok, held := w.rlUnknown.Allow(nowMS(), wire.LogEveryMS); ok {
			w.h.logf("пир %s не описан в конфигурации — отказ%s",
				conf.KeyFP(hs.PeerStatic), wire.HeldSuffix(held))
		}
		w.h.stats.strangers.Add(1)
		w.onStranger(k, s, seg, nil)
		return
	}
	// Воспроизведение записанного msg1: метка времени обязана быть новее прошлой от этого пира.
	// Само по себе это не даёт атакующему сессию (подтверждение он не подделает), но даёт хабу три
	// зря потраченных X25519 на каждый повтор.
	w.h.ctl.Lock()
	seen := w.h.lastStamp[found]
	w.h.ctl.Unlock()
	if hs.Peer.Stamp != 0 && hs.Peer.Stamp < seen {
		if ok, held := w.rlStamp.Allow(nowMS(), wire.LogEveryMS); ok {
			w.h.logf("пир %d: метка времени старее прошлой — похоже на повтор%s",
				found+1, wire.HeldSuffix(held))
		}
		w.free(k, s)
		return
	}
	s.peer = found

	// Хаб называет свой предел так же, как пир: MTU настоящего канала минус накладные, но не
	// больше заданного в конфигурации. Из этих двух чисел стороны берут минимум.
	own := wire.MTUDefault
	if mtu, _ := link.EgressMTU(seg.DAddr); mtu > 0 {
		own = wire.MTU(mtu)
	}
	if c := w.h.opt.Conf.MTU; c > 0 && c < own {
		own = c
	}
	out, tx, rx, err := hs.ServerWrite(own)
	if err != nil {
		w.h.logf("ответ на рукопожатие не собрался: %v", err)
		w.free(k, s)
		return
	}
	if err := s.conn.Send(link.PSH|link.ACK, out); err != nil {
		w.h.logf("ответ на рукопожатие не ушёл: %v", err)
		w.free(k, s)
		return
	}
	s.hs, s.tx, s.rx = hs, tx, rx
	s.phase = phHS
}

// confirm — подтверждение пира: после него сессия несёт данные.
func (w *worker) confirm(k skey, s *session, seg *link.Seg) {
	if _, err := s.hs.ServerConfirm(s.rx, seg.Payload); err != nil {
		w.h.logf("подтверждение пира не сошлось: %v", err)
		w.free(k, s)
		return
	}
	peerMTU := int(s.hs.Peer.MTU)
	// Метку времени и номер соединения снимаем ДО очистки состояния рукопожатия: Wipe затирает его
	// целиком. В движке на C первая версия читала уже занулённое поле, и защита от повтора
	// превращалась в «последняя метка всегда ноль», то есть в её отсутствие.
	stamp := s.hs.Peer.Stamp
	connID := s.hs.Peer.ConnID()
	if connID >= wire.ConnsMax {
		connID = 0
	}
	s.hs.Wipe()
	s.hs = nil
	s.win.Reset()
	s.connID = connID
	s.phase = phEst
	s.handshakeAt = time.Now()

	w.h.ctl.Lock()
	w.h.lastStamp[s.peer] = stamp
	w.h.ctl.Unlock()
	// Одна сессия на соединение пира: новая заменяет прежнюю. Прежнюю мы здесь НЕ освобождаем —
	// она может принадлежать другому воркеру, и её запись лежит в ЕГО таблице. Вместо этого она
	// остаётся «смещённой» и её убирает свой владелец в своём же обслуживании: признак — привязка
	// пир→сессия указывает не на неё. Трафика она не несёт с этой секунды, потому что пир в неё
	// больше не отправляет.
	w.h.peerSess[s.peer][connID].Store(s)

	kind := "ChaCha20-Poly1305"
	if s.tx.Kind() == noise.AEADAES128 {
		kind = "AES-128-GCM"
	}
	w.h.logf("пир %s поднялся с %s:%d, MTU %d, шифр %s", conf.KeyFP(w.h.opt.Conf.Peers[s.peer].Pub),
		ip4b(k.addr), k.port, peerMTU, kind)
}

// onData — собрать запись, расшифровать и развести пакеты.
func (w *worker) onData(s *session, seg *link.Seg) {
	// Сборка записи, которая могла быть разрезана между сегментами. Она же предфильтр: сегмент, не
	// начинающийся с заголовка записи и не продолжающий начатую, отбрасывается до криптографии.
	body, hdr, rel, done := s.reasm.Feed(seg.Seq, s.conn.ISNRX(), seg.Payload)
	if !done {
		return
	}
	if !s.win.Check(rel) {
		return
	}
	pt, err := s.rx.Open(body, hdr, uint64(rel))
	if err != nil {
		return
	}
	// Коммит окна ТОЛЬКО после сошедшегося тега: иначе подделанный пакет с далёким смещением
	// выбил бы из окна весь честный поток.
	s.win.Commit(rel)
	if len(pt) > 0 && pt[0] == wire.CtlBatch {
		if !wire.BatchIter(pt, func(f []byte) { w.onFrame(s, f) }) {
			w.h.stats.dropped.Add(1)
		}
		return
	}
	w.onFrame(s, pt)
}

// onFrame — один кадр открытого текста от пира.
func (w *worker) onFrame(s *session, pt []byte) {
	s.upPkts++
	w.h.stats.rxPkts.Add(1)
	w.h.stats.rxBytes.Add(uint64(len(pt)))
	switch wire.FrameKind(pt) {
	case wire.KindCtl:
		w.onCtl(s, pt)
	case wire.KindIPv4, wire.KindIPv6:
		// Копия обязательна: пакет поедет дальше из строки с местом под заголовки впереди, а
		// пришёл он в приёмном буфере, где такого места нет.
		n := copy(w.row[wire.HdrRoom:], pt)
		w.route(s, w.row[wire.HdrRoom:wire.HdrRoom+n])
	}
	// keepalive молча учтён: он уже обновил время последнего приёма.
}

// onCtl — служебные кадры пира: проба пути и итог согласования.
func (w *worker) onCtl(s *session, pt []byte) {
	// Проба пути: отвечаем эхом с ДОШЕДШИМ размером. Эхо крохотное (три байта), поэтому оно
	// проходит всегда — иначе пир не смог бы отличить «большой кадр не дошёл» от «не дошёл ответ».
	if psz := wire.ProbeSize(pt); psz > 0 {
		n := wire.PackBuild(w.row[wire.HdrRoom:], psz)
		w.sendTo(s, w.row, n)
		return
	}
	// Пир не собирает наши записи: путь рвёт сегменты. Схлопываем пачку немедленно — на рваном
	// пути она делает хуже, а не лучше.
	if n := wire.LossValue(pt); n > 0 {
		s.batchMax = 1
		s.coolUntil = nowMS() + reasmCooldownMS
		if ok, held := w.rlProbe.Allow(nowMS(), wire.LogEveryMS); ok {
			w.h.logf("пир не собрал %d записей — везу по одному кадру%s", n, wire.HeldSuffix(held))
		}
		return
	}
	// Итог согласования: пир проверил путь и называет рабочий размер. Берём минимум со своим
	// пределом — больше него мы всё равно не отправим.
	if mv := wire.MTUValue(pt); mv > 0 {
		own := w.h.opt.Conf.MTU
		if own == 0 {
			own = wire.MTUDefault
		}
		was := s.mtu
		s.mtu = mv
		if own < mv {
			s.mtu = own
		}
		// Печатаем только ИЗМЕНЕНИЕ: кадр приходит после каждого пробоя пира, то есть раз в две
		// минуты на каждого, и строка «согласован тот же MTU» через год работы звезды из тридцати
		// пиров — это четверть миллиона строк ни о чём.
		if s.mtu != was && s.peer >= 0 {
			w.h.logf("пир %s: согласован MTU %d", conf.KeyFP(w.h.opt.Conf.Peers[s.peer].Pub), s.mtu)
		}
		w.h.retuneMTU()
	}
}

// route — расшифрованный пакет: проверить право на адрес источника и развести.
func (w *worker) route(from *session, pt []byte) {
	if len(pt) < 20 || from.peer < 0 {
		return
	}
	src := binary.BigEndian.Uint32(pt[12:16])
	dst := binary.BigEndian.Uint32(pt[16:20])
	// ОБЯЗАТЕЛЬНАЯ проверка: без неё один скомпрометированный пир подделывает трафик любого
	// другого. Право на адрес даёт конфигурация, а не сам пакет.
	if !route.SrcOK(&w.h.opt.Conf.Peers[from.peer], src) {
		w.h.stats.dropped.Add(1)
		return
	}
	to := w.h.router.Lookup(dst, nil)
	if to >= 0 && to != from.peer {
		if d := w.h.pick(to, pt); d != nil {
			// Пир↔пир: уменьшаем TTL (иначе петля в звезде живёт вечно) и шифруем В ТОЙ ЖЕ строке.
			if !route.TTLDec(pt) {
				return
			}
			// Подрезка по MTU ПОЛУЧАТЕЛЯ: у пиров он свой у каждого, и путь между ними — узкое
			// место из двух. Кроме хаба это посчитать некому: пиры друг о друге ничего не знают.
			if d.mtu > 0 {
				route.MSSClamp(pt, d.mtu)
			}
			w.sendTo(d, w.row, len(pt))
			return
		}
	}
	// Свой адрес или выход наружу — отдаём ядру, в СВОЮ очередь устройства.
	if w.dev != nil {
		if _, err := w.dev.Write(pt); err != nil {
			w.h.stats.dropped.Add(1)
		}
		return
	}
	w.h.stats.dropped.Add(1)
}

// tunLoop — из ядра (интернет и локальные ответы) к пирам.
//
// Это ГЛАВНОЕ направление загрузки, и именно здесь пачка окупается: подряд идущие пакеты одному и
// тому же пиру уезжают одной записью, которая больше сегмента и потому разрезается между ними —
// ровно так, как ведёт себя настоящий TLS. Ждать ради пачки нечего: чтение неблокирующее, берётся
// только то, что уже пришло.
func (w *worker) tunLoop(ctx context.Context) {
	row := make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag)
	slab := make([]byte, wire.BatchFramesMax*wire.MTUDefault)
	frames := make([][]byte, 0, wire.BatchFramesMax)
	for ctx.Err() == nil {
		ok, err := w.dev.WaitRead(200 * time.Millisecond)
		if err != nil {
			return
		}
		if !ok {
			continue
		}
		frames = frames[:0]
		used, total := 0, wire.BatchHdr
		var dst *session
		for {
			if len(frames) > 0 && (len(frames) >= dst.batchMax ||
				total+2+wire.MTUDefault > wire.MaxRecord) {
				break
			}
			n, err := w.dev.Read(slab[used : used+wire.MTUDefault])
			if err != nil || n <= 20 {
				break
			}
			pkt := slab[used : used+n]
			to := w.h.router.Lookup(binary.BigEndian.Uint32(pkt[16:20]), nil)
			var d *session
			if to >= 0 {
				d = w.h.pick(to, pkt)
			}
			if d == nil {
				continue // нет живого соединения к этому пиру — отбросить, память не тратим
			}
			if d.mtu > 0 {
				route.MSSClamp(pkt, d.mtu)
			}
			// Пачка собирается только для ОДНОГО получателя: у каждой сессии свои ключи и свой
			// номер последовательности, и «одна запись двум пирам» бессмысленна. Пакет другому
			// пиру закрывает набор и уезжает следующим кругом сам.
			if dst != nil && d != dst {
				w.sendFrames(dst, row, frames)
				frames = frames[:0]
				used, total = 0, wire.BatchHdr
				n = copy(slab, pkt)
				pkt = slab[:n]
			}
			dst = d
			frames = append(frames, pkt)
			used += n
			total += 2 + n
		}
		if len(frames) > 0 && dst != nil {
			w.sendFrames(dst, row, frames)
		}
	}
}

// batchFull — влезет ли ещё один кадр в запись.
func batchFull(frames [][]byte, next int) bool {
	total := wire.BatchHdr
	for _, f := range frames {
		total += 2 + len(f)
	}
	return total+2+next > wire.MaxRecord
}

// sendFrames увозит кадры одной записью: один кадр — как есть, несколько — в контейнере.
func (w *worker) sendFrames(d *session, row []byte, frames [][]byte) {
	if len(frames) == 1 {
		n := copy(row[wire.HdrRoom:], frames[0])
		w.sendTo(d, row, n)
		return
	}
	n := wire.BatchBuild(row[wire.HdrRoom:], frames)
	if n == 0 {
		w.h.stats.dropped.Add(uint64(len(frames)))
		return
	}
	w.sendTo(d, row, n)
}

// pick — выбрать соединение пира для этого пакета.
//
// Соединений у пира несколько (по одному на его воркер), и выбор ОБЯЗАН быть постоянным для
// потока: раскидай мы пакеты одного соединения TCP по разным путям — получатель увидит
// переставленные пакеты, а это для него неотличимо от потерь и рушит скорость сильнее, чем помогает
// второе ядро.
//
// Хеш берётся от внутренних адресов и портов, слот — по кругу от него до первого живого. Изменение
// числа живых соединений переставит потоки один раз, и это допустимо: событие редкое.
func (h *Hub) pick(peer int, pt []byte) *session {
	if peer < 0 || peer >= conf.PeersMax {
		return nil
	}
	start := int(route.FlowHash(pt) % wire.ConnsMax)
	for k := 0; k < wire.ConnsMax; k++ {
		if s := h.peerSess[peer][(start+k)%wire.ConnsMax].Load(); s != nil {
			return s
		}
	}
	return nil
}

// sendTo — зашифровать пакет для сессии и отправить.
//
// Открытый текст лежит по row[wire.HdrRoom:], ровно там, где он оказался после расшифровки
// входящего. Всё — под замком сессии: отправлять в неё может любой воркер, а выдача смещения,
// шифрование им и запись заголовка обязаны быть неделимы (повтор nonce = полная потеря стойкости).
func (w *worker) sendTo(d *session, row []byte, plen int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.phase != phEst || d.tx == nil {
		return
	}
	// Сессия по НАСТОЯЩЕМУ потоку: резать запись на сегменты не нужно, это работа ядра.
	if d.st != nil {
		// Заворота nonce здесь больше не может быть: смещение в потоке 64-битное (см. шапку
		// wire.Stream), поэтому ни закрывать поток, ни менять ключи по объёму не нужно. Ветка
		// поддельного TCP ниже ретайрится по-прежнему, и там это неизбежно: nonce берётся из
		// относительного номера последовательности TCP, а он 32-битный по своей природе.
		rec := row[wire.HdrRoom-wire.RecHdr : wire.HdrRoom]
		err := d.st.WriteRecord(row, wire.RecHdr+plen+wire.Tag, func(rel uint64) error {
			if err := wire.RecBuild(rec, plen+wire.Tag); err != nil {
				return err
			}
			_, e := d.tx.Seal(row[wire.HdrRoom:wire.HdrRoom+plen+wire.Tag], plen, rec, rel)
			return e
		})
		if err != nil {
			w.h.stats.dropped.Add(1)
			return
		}
		d.downPkts++
		w.h.stats.txPkts.Add(1)
		w.h.stats.txBytes.Add(uint64(plen))
		return
	}
	if wire.RetireDue(d.conn.RelNext(), d.conn.Age()) {
		return
	}
	rec := row[wire.HdrRoom-wire.RecHdr : wire.HdrRoom]
	mtu := d.mtu
	if mtu <= 0 {
		mtu = wire.MTUDefault
	}
	maxSeg := mtu + wire.Overhead - 40
	err := d.conn.SendRecord(row, wire.RecHdr+plen+wire.Tag, maxSeg, w.scratch, func(rel uint32) error {
		if err := wire.RecBuild(rec, plen+wire.Tag); err != nil {
			return err
		}
		_, err := d.tx.Seal(row[wire.HdrRoom:wire.HdrRoom+plen+wire.Tag], plen, rec, uint64(rel))
		return err
	})
	if err != nil {
		w.h.stats.dropped.Add(1)
		return
	}
	d.downPkts++
	w.h.stats.txPkts.Add(1)
	w.h.stats.txBytes.Add(uint64(plen))
}

// maintain — обслуживание СВОИХ сессий: уборка, keepalive, подтверждения.
func (w *worker) maintain() {
	for k, s := range w.sess {
		// Сессию, помеченную к уборке (например, прикрытие закрылось), убирает ВЛАДЕЛЕЦ: таблица
		// его личная.
		if s.dead.Load() {
			if s.up != nil {
				s.up.Close()
			}
			w.free(k, s)
			continue
		}
		if s.conn.Idle() > IdleMS {
			w.free(k, s)
			continue
		}
		// Смещённая сессия: пир пересоединился с другого порта, привязка пир→сессия указывает уже
		// не на нас. Убирает её именно ВЛАДЕЛЕЦ — тот, в чьей таблице она лежит.
		if s.phase == phEst && s.peer >= 0 && s.connID >= 0 {
			if cur := w.h.peerSess[s.peer][s.connID].Load(); cur != nil && cur != s {
				w.free(k, s)
				continue
			}
		}
		// Обратная связь по сборке: если у НАС не собираются записи пира, сказать об этом обязаны
		// мы — уменьшить пачку может только он.
		if s.phase == phEst {
			now := nowMS()
			if drops := s.reasm.Dropped; drops > s.lastDrops && now-s.lastReport >= reasmReportMS {
				if n := wire.LossBuild(w.row[wire.HdrRoom:wire.HdrRoom+8], int(drops-s.lastDrops)); n > 0 {
					w.sendTo(s, w.row, n)
					s.lastDrops = drops
					s.lastReport = now
				}
			}
			if !w.h.opt.NoBatch && now >= s.coolUntil && now-s.lastGrow >= reasmGrowMS &&
				s.batchMax < wire.BatchFramesMax {
				s.batchMax *= 2
				if s.batchMax > wire.BatchFramesMax {
					s.batchMax = wire.BatchFramesMax
				}
				s.lastGrow = now
			}
		}
		// Пустая запись и есть keepalive: длина нагрузки ноль, тип кадра пир опознаёт по пустоте.
		// Отдельного вида кадра для этого не нужно.
		// Keepalive с разбросом по той же причине, что у клиента: ровный интервал находится
		// подсчётом пауз между мелкими пакетами и не встречается в браузерных соединениях.
		if s.phase == phEst {
			if s.keepNext == 0 {
				s.keepNext = KeepaliveMS*8/10 + mrand.Int64N(KeepaliveMS*4/10+1)
			}
			if s.conn.NeedKeepalive(s.keepNext) {
				w.sendTo(s, w.row, 0)
				s.keepNext = KeepaliveMS*8/10 + mrand.Int64N(KeepaliveMS*4/10+1)
			}
		}
		if err := s.conn.Tick(); err != nil {
			w.free(k, s)
		}
	}
}

// sendRST — ответ тому, чьей сессии у нас нет.
func (w *worker) sendRST(seg *link.Seg) {
	if w.tx0 == nil || seg.Flags&link.RST != 0 {
		return
	}
	sender, ok := w.tx0.(interface {
		SendTo(seg []byte, daddr [4]byte) error
	})
	if !ok {
		return
	}
	buf := make([]byte, 60)
	n := link.BuildSeg(buf, seg.DAddr, seg.SAddr, uint16(w.h.opt.Conf.ListenPort), seg.SPort,
		seg.Ack, seg.Seq+uint32(len(seg.Payload)), link.RST|link.ACK, link.OptNone, nil)
	_ = sender.SendTo(buf[:n], seg.SAddr)
}

// retuneMTU — MTU устройства по минимуму среди пиров.
//
// Зовётся редко (раз на пробой пира) и из любого воркера, поэтому целиком под общим замком: он же
// защищает применённое значение, иначе два воркера могли бы одновременно решить, что оно
// изменилось, и дважды дёрнуть настройку устройства.
func (h *Hub) retuneMTU() {
	if len(h.dev) == 0 {
		return
	}
	h.ctl.Lock()
	defer h.ctl.Unlock()
	best := 0
	for p := 0; p < conf.PeersMax; p++ {
		for c := 0; c < wire.ConnsMax; c++ {
			s := h.peerSess[p][c].Load()
			if s == nil || s.mtu <= 0 {
				continue
			}
			if best == 0 || s.mtu < best {
				best = s.mtu
			}
		}
	}
	if best == 0 || best == h.devMTU {
		return
	}
	if err := h.dev[0].SetMTU(best); err != nil {
		h.logf("не удалось поставить MTU устройства %d: %v", best, err)
		return
	}
	h.logf("MTU устройства: %d (минимум среди пиров)", best)
	h.devMTU = best
}

func nowMS() int64 { return time.Now().UnixNano() / int64(time.Millisecond) }

func ip4str(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func ip4b(a [4]byte) string { return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]) }
