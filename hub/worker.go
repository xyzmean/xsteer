package hub

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
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
	w.sess[k] = &session{conn: conn, phase: phSyn, peer: -1, connID: -1}
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
func (w *worker) handshake(k skey, s *session, seg *link.Seg) {
	hs := &noise.HS{}
	if err := hs.ServerRead(w.h.opt.Sec.Priv, seg.Payload, nil); err != nil {
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

// onData — расшифровать запись и развести пакет.
func (w *worker) onData(s *session, seg *link.Seg) {
	body, err := wire.RecParse(seg.Payload)
	if err != nil {
		return
	}
	rel := s.conn.RelOf(seg.Seq)
	if !s.win.Check(rel) {
		return
	}
	// Расшифровка НА МЕСТЕ, в приёмном буфере сегмента. Открытый текст оказывается там же, где
	// лежал шифротекст, поэтому пересылка другому пиру не требует копии... но копия ОДНА всё же
	// нужна: приёмный буфер не имеет запаса под заголовки впереди (сегмент пришёл со своим
	// заголовком IP переменной длины), а исходящий пакет собирается «заголовки перед нагрузкой».
	// Перенос делается один раз и только для пакетов, которые действительно пойдут дальше.
	pt, err := s.rx.Open(body, seg.Payload[:wire.RecHdr], uint64(rel))
	if err != nil {
		return
	}
	// Коммит окна ТОЛЬКО после сошедшегося тега: иначе подделанный пакет с далёким смещением
	// выбил бы из окна весь честный поток.
	s.win.Commit(rel)
	s.upPkts++
	w.h.stats.rxPkts.Add(1)
	w.h.stats.rxBytes.Add(uint64(len(pt)))

	switch wire.FrameKind(pt) {
	case wire.KindCtl:
		w.onCtl(s, pt)
	case wire.KindIPv4, wire.KindIPv6:
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
func (w *worker) tunLoop(ctx context.Context) {
	row := make([]byte, wire.Row+wire.Tag)
	for ctx.Err() == nil {
		n, err := w.dev.Read(row[wire.HdrRoom : wire.HdrRoom+wire.MTUDefault])
		if err != nil {
			return
		}
		if n <= 20 {
			continue
		}
		pt := row[wire.HdrRoom : wire.HdrRoom+n]
		dst := binary.BigEndian.Uint32(pt[16:20])
		to := w.h.router.Lookup(dst, nil)
		if to < 0 {
			continue
		}
		d := w.h.pick(to, pt)
		if d == nil {
			continue // нет живого соединения к этому пиру — отбросить
		}
		if d.mtu > 0 {
			route.MSSClamp(pt, d.mtu)
		}
		w.sendTo(d, row, n)
	}
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
	if wire.RetireDue(d.conn.RelNext(), d.conn.Age()) {
		return
	}
	rec := row[wire.HdrRoom-wire.RecHdr : wire.HdrRoom]
	err := d.conn.SendData(row, wire.RecHdr+plen+wire.Tag, func(rel uint32) error {
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
		// Пустая запись и есть keepalive: длина нагрузки ноль, тип кадра пир опознаёт по пустоте.
		// Отдельного вида кадра для этого не нужно.
		if s.phase == phEst && s.conn.NeedKeepalive(KeepaliveMS) {
			w.sendTo(s, w.row, 0)
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
