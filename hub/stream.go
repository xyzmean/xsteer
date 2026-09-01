package hub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/xyzmean/xsteer/conf"
	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/wire"
)

// Режим потока на хабе: слушающий сокет ядра вместо поддельного TCP.
//
// ПОЧЕМУ ОТДЕЛЬНЫЙ ПОРТ, А НЕ ТОТ ЖЕ. Слушающий сокет ядра отвечает SYN-ACK всякому, кто
// постучится, — включая пиров, которые ведут ПОДДЕЛЬНЫЙ TCP. Тогда на один их SYN приходит два
// ответа с разными начальными номерами, и сессия рассыпается. Поэтому режимы живут на разных
// портах; какой из них поставить на :443, решает оператор (поток выглядит настоящим TLS полнее,
// поддельный TCP экономит повторы).
//
// Что даёт слушающий сокет сверх облика: защиту от потока SYN обеспечивает ядро (syncookies), а
// проксирование неопознанных к сайту-прикрытию перестаёт зависеть от отсутствия повторных передач —
// та единственная дырка в защите от зондирования, которую пришлось назвать неустранимой.

// streamIdle — после какой тишины сессия потока считается мёртвой. Значение то же, что у поддельного
// TCP (IdleMS): половины протокола обязаны сходиться в том, когда пир считается пропавшим. Живому
// соединению этот срок недостижим с запасом в девяносто раз — пир присылает пробу живости каждые
// streamProbeMS, то есть раз в две секунды. Переменная, а не константа, только затем, чтобы стенду
// не приходилось ждать три минуты.
var streamIdle = time.Duration(IdleMS) * time.Millisecond

// streamMax — сколько соединений потока хаб держит одновременно.
//
// Предел обязателен, а не «на всякий случай»: соединение занимает горутину и приёмный буфер до
// пятнадцатисекундного срока рукопожатия, и НИЧЕГО из этого не требует, чтобы стучащийся был
// описанным пиром — порт публичный по построению. Без предела объём занятой памяти и число
// занятых дескрипторов выбирал бы тот, кто стучится.
//
// Число то же, что у таблицы сессий (SessTotal), и по той же причине: законная звезда — 32 пира
// по 4 соединения, то есть 128, — входит в него с двойным запасом на переподключение без
// разрыва. Отказать законному пиру этот предел поэтому не может.
//
// Переменная, а не константа, только затем, чтобы стенду не требовалось 256 соединений.
var streamMax int64 = SessTotal

// streamAcceptPause — пауза после НЕУДАЧНОГО accept. Нужна, чтобы цикл не крутился на полной
// скорости, пока причина не пройдёт: кончившиеся дескрипторы освобождаются не мгновенно.
var streamAcceptPause = 20 * time.Millisecond

// streamListen поднимает слушателя и обслуживает соединения до отмены контекста.
func (h *Hub) streamListen(ctx context.Context, port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("слушатель потока на :%d: %w", port, err)
	}
	h.logf("слушаю настоящий TCP :%d (режим потока)", port)
	return h.streamServe(ctx, ln)
}

// streamServe принимает соединения с готового слушателя. Отдельно от streamListen затем, чтобы
// стенд мог подставить свой: ни ошибку accept, ни исчерпание дескрипторов настоящим сокетом не
// воспроизвести.
func (h *Hub) streamServe(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for ctx.Err() == nil {
		nc, err := ln.Accept()
		if err != nil {
			// РАЗЛИЧАТЬ «СЛУШАТЕЛЬ ЗАКРЫТ» И «НЕ ВЫШЛО ПРИНЯТЬ ЭТОГО». Прежде здесь стоял
			// `return err` на любую ошибку, то есть слушатель умирал НАВСЕГДА от чего угодно:
			// кончились дескрипторы процесса, соединение отвалилось между SYN и accept
			// (ECONNABORTED), ядро вернуло EMFILE под потоком. Хаб при этом оставался жив,
			// поддельный TCP работал, а половина потока молча перестала принимать — и снаружи
			// это выглядит как беда сети, потому что ни в журнале, ни в состоянии следа нет.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			if ok, held := h.rlAccept.Allow(nowMS(), wire.LogEveryMS); ok {
				h.logf("слушатель потока: принять не удалось (%v) — продолжаю принимать%s",
					err, wire.HeldSuffix(held))
			}
			time.Sleep(streamAcceptPause)
			continue
		}
		// Место под соединение занимается ДО горутины: иначе предел проверялся бы уже после
		// того, как горутина и буферы созданы, то есть не проверялся бы вовсе.
		if h.streamLive.Add(1) > streamMax {
			h.streamLive.Add(-1)
			if ok, held := h.rlStream.Allow(nowMS(), wire.LogEveryMS); ok {
				h.logf("соединений потока больше %d одновременно — этому отказываю%s",
					streamMax, wire.HeldSuffix(held))
			}
			nc.Close()
			continue
		}
		// Соединение потока учитывается в общем счётчике горутин, а не живёт само по себе: его
		// обработчик пишет пакеты В УСТРОЙСТВО (onFrame), и завершение обязано дождаться его
		// прежде, чем закрыть дескриптор устройства (I-109). Add здесь безопасен: сама
		// streamServe тоже в счётчике и держит его больше нуля, пока принимает соединения.
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			defer h.streamLive.Add(-1)
			h.streamConn(ctx, nc)
		}()
	}
	return ctx.Err()
}

// streamConn обслуживает одно соединение: рукопожатие, потом данные.
func (h *Hub) streamConn(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	if tc, ok := nc.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		// Буферы, как и у пира, оставлены автоподстройке — см. шапку wire/stream.go: пришпиленный
		// setsockopt резал приёмный буфер хаба до 416 КБ, то есть до 47 Мбит/с на 72 мс задержки.
	}
	peerAddr := nc.RemoteAddr().String()
	st := wire.NewStream(nc)

	// Рукопожатие с крышкой по времени: соединение, которое молчит после SYN, не должно занимать
	// горутину и память бесконечно — на публичный порт стучится кто угодно.
	_ = nc.SetDeadline(time.Now().Add(15 * time.Second))

	// ClientHello приходит одной записью (тип 0x16): читаем заголовок, потом тело.
	var hdr [wire.RecHdr]byte
	if err := st.ReadFull(hdr[:]); err != nil {
		return
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	// Не похоже на рукопожатие TLS вовсе — отвечаем как настоящий сервер и уходим. Молчание здесь
	// отличимо не хуже, чем молчание на Hello (см. onStranger).
	if hdr[0] != 0x16 || hdr[1] != 0x03 || n < 100 || n > 4096 {
		h.stats.strangers.Add(1)
		_, _ = nc.Write(noise.Alert())
		return
	}
	rec := make([]byte, wire.RecHdr+n)
	copy(rec, hdr[:])
	if err := st.ReadFull(rec[wire.RecHdr:]); err != nil {
		return
	}

	hs := &noise.HS{}
	if err := hs.ServerRead(h.opt.Sec.Priv, rec, nil); err != nil {
		h.stats.strangers.Add(1)
		_, _ = nc.Write(noise.Alert())
		return
	}
	found := h.findPeer(hs.PeerStatic)
	if found < 0 {
		h.stats.strangers.Add(1)
		h.logf("поток с %s: пир %s не описан в конфигурации — отказ", peerAddr,
			conf.KeyFP(hs.PeerStatic))
		_, _ = nc.Write(noise.Alert())
		return
	}
	// Защита от воспроизведения — та же и та же общая: пир приходит с разных портов, а метка
	// времени одна на пира.
	if !h.replayFresh(found, hs.Peer.Stamp) {
		h.logf("поток с %s: метка времени старее прошлой — похоже на повтор", peerAddr)
		// Повтор записанного msg1 — тоже «не наш», и отвечать на него ИНАЧЕ, чем прочим
		// неопознанным, значит рассказывать прибору, что этот Hello он подобрал правильно.
		// Прежде эта ветка закрывала соединение молча и никого не считала, то есть отвечала
		// молчанием там, где три соседние развилки отвечают оповещением. Та же правка и по той же
		// причине сделана на половине поддельного TCP (worker.go, handshake) и в реализации на C
		// (xshub.c, hs_step).
		h.stats.strangers.Add(1)
		_, _ = nc.Write(noise.Alert())
		return
	}

	own := wire.MTUDefault
	if c := h.opt.Conf.MTU; c > 0 && c < own {
		own = c
	}
	out, tx, rx, err := hs.ServerWrite(own)
	if err != nil {
		return
	}
	if err := st.WriteRaw(out); err != nil {
		return
	}
	// Подтверждение пира: одна запись известной длины.
	var chdr [wire.RecHdr]byte
	if err := st.ReadFull(chdr[:]); err != nil {
		return
	}
	cn := int(chdr[3])<<8 | int(chdr[4])
	if chdr[0] != 0x17 || cn != noise.FinBody {
		return
	}
	cbuf := make([]byte, wire.RecHdr+cn)
	copy(cbuf, chdr[:])
	if err := st.ReadFull(cbuf[wire.RecHdr:]); err != nil {
		return
	}
	if _, err := hs.ServerConfirm(rx, cbuf); err != nil {
		h.logf("поток с %s: подтверждение не сошлось", peerAddr)
		return
	}
	connID := hs.Peer.ConnID()
	if connID >= wire.ConnsMax {
		connID = 0
	}
	stamp := hs.Peer.Stamp
	peerMTU := int(hs.Peer.MTU)
	hs.Wipe()
	_ = nc.SetDeadline(time.Time{})

	s := &session{
		st: st, nc: nc, tx: tx, rx: rx, phase: phEst, peer: found, connID: connID,
		handshakeAt: time.Now(),
	}
	s.batchMax.Store(wire.BatchFramesMax)
	if peerMTU > 0 {
		// Своим пределом зажимается и здесь: число приехало из провода, а по s.mtu считается
		// подрезка MSS для трафика пир↔пир. Тот же потолок, что в worker.onCtl.
		if peerMTU > own {
			peerMTU = own
		}
		s.mtu.Store(int32(peerMTU))
	}
	h.commitStamp(found, stamp)
	h.peerSess[found][connID].Store(s)
	defer h.peerSess[found][connID].CompareAndSwap(s, nil)

	kind := "ChaCha20-Poly1305"
	if tx.Kind() == noise.AEADAES128 {
		kind = "AES-128-GCM"
	}
	// Ратчет эпох — на обоих направлениях и до первой записи данных, как и у пира.
	tx.EnableEpochs()
	rx.EnableEpochs()
	h.logf("пир %s поднялся потоком с %s, MTU %d, шифр %s, ключи меняются каждые %d МиБ",
		conf.KeyFP(h.opt.Conf.Peers[found].Pub), peerAddr, peerMTU, kind, noise.EpochBytes>>20)

	// Воркер на соединение: он нужен обработке кадров как хозяин буфера пересылки и очереди
	// устройства. Заводить его на соединение дешевле, чем протаскивать эти две вещи параметрами
	// через весь путь данных, а память — восемь килобайт на пира.
	w := &worker{h: h, row: make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag),
		sess: map[skey]*session{}, sessMax: sessPerWorker(1)}
	if len(h.dev) > 0 {
		w.dev = h.dev[found%len(h.dev)]
	}

	// Контекст СОЕДИНЕНИЯ, производный от контекста хаба: горутина ниже будит блокирующее чтение
	// закрытием сокета (у потока нет опроса с таймаутом), и жить она обязана столько же, сколько
	// соединение. Пока она ждала отмены ХАБА, каждое поднявшееся соединение оставляло её до
	// остановки процесса — дескриптор закрывал defer, а стек горутины оставался (I-133). У пира то
	// же место сделано так же: client/stream.go, sctx/stop.
	cctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		<-cctx.Done()
		nc.Close()
	}()
	for {
		// Срок на КАЖДОЕ чтение, а не один на соединение: это единственная уборка, какая у сессии
		// потока есть вообще. Обслуживание (w.maintain) зовётся только из rxLoop, то есть с
		// половины поддельного TCP, и воркер этого соединения туда не попадает никогда — значит
		// уборку по простою обязано делать само чтение (I-132). Именно SetReadDeadline, а не
		// SetDeadline: в это соединение пишут ДРУГИЕ воркеры, пересылая трафик пир↔пир, и срок на
		// запись оборвал бы их.
		_ = nc.SetReadDeadline(time.Now().Add(streamIdle))
		body, rhdr, rel, err := st.ReadRecord()
		if err != nil {
			s.mu.Lock()
			s.phase = phFree
			s.mu.Unlock()
			return
		}
		pt, err := rx.Open(body, rhdr, rel)
		if err != nil {
			// В потоке испорченная запись означает конец: границы следующей известны только из
			// длины, которой мы уже не верим.
			s.mu.Lock()
			s.phase = phFree
			s.mu.Unlock()
			return
		}
		if len(pt) > 0 && pt[0] == wire.CtlBatch {
			if !wire.BatchIter(pt, func(f []byte) { w.onFrame(s, f) }) {
				h.stats.dropped.Add(1)
			}
			continue
		}
		w.onFrame(s, pt)
	}
}
