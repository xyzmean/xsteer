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
	"github.com/xyzmean/xsteer/tun"
	"github.com/xyzmean/xsteer/wire"
)

// rxLoop — приём от пиров и обслуживание своих сессий.
//
// Обслуживание идёт ЗДЕСЬ ЖЕ, а не в отдельной горутине, и это не экономия: таблица сессий
// принадлежит этому воркеру, и трогать её из второй горутины значило бы завести замок на пути,
// который и так под потоком.
func (w *worker) rxLoop(ctx context.Context) {
	buf := make([]byte, wire.RowRX)
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
			// Заход кончился — отдаём ядру то, что накопила разгрузка сегментации устройства.
			// Пакеты, ушедшие в устройство внутри захода, склеены в супер-кадр и уезжают одним
			// вызовом вместо сорока пяти; сброс ровно здесь, на границе всплеска, поэтому задержки
			// это не добавляет. Без сброса последний пакет лежал бы до следующего события.
			if w.dev != nil {
				if err := w.dev.Flush(); err != nil {
					w.h.stats.dropped.Add(1)
				}
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
		w.onSyn(k, s, seg)
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

// onSyn — поддельный SYN на нашем порту.
//
// СЕССИЮ В РАБОТЕ SYN НЕ ТРОГАЕТ, и это несущее правило: поддельный SYN не несёт ни байта
// аутентификации — такой сегмент собирает кто угодно, кто знает адрес хаба и порт пира. Прежде эта
// ветка безусловно переписывала isnRX, то есть базу, из которой считается смещение принятой записи,
// а из смещения выводится nonce расшифровки: одно постороннее сообщение останавливало входящий
// поток пира целиком. Отвечать на такой SYN тоже нельзя — RST оборвал бы туннель настоящему пиру,
// то есть подсказал бы отправителю, как этот туннель гасить.
//
// НО ПРОСТО ОТБРОСИТЬ — МАЛО, и вот чего здесь не хватало. Пир, поднявшийся заново без паузы (смена
// сети, выход из сна, перезапуск службы), может прийти с ТОЙ ЖЕ четвёркой, и тогда его SYN попадал
// ровно в эту ветку: ответом была тишина до тех пор, пока прежняя сессия не умрёт по простою.
// Снаружи это выглядело как «пир не подключается», и ждать приходилось минуты.
//
// Поэтому SYN в живую сессию теперь ЗАПУСКАЕТ ПРОБУ: «сессия, ты ещё куда-нибудь ведёшь?». Ответа
// на сам SYN по-прежнему нет и состояние сессии по-прежнему не меняется — но если прежний путь
// мёртв (а при вернувшемся пире он мёртв), проба это выясняет за 450 мс и сессия уходит. Повтор SYN
// придёт через секунду и заведёт новую сессию как обычно.
//
// ЦЕНА ПРИ ПОДДЕЛКЕ НАЗВАНА ПРЯМО: посторонний, знающий четвёрку живого туннеля, может заставить
// хаб отправить пиру три пустые записи. Пир на них ответит, проба это увидит, сессия останется. То
// есть подделка стоит нападающему одного пакета, а нам — трёх пустых записей и ничего больше; это
// несравнимо дешевле, чем то, что стоило прежнее решение настоящему пиру.
func (w *worker) onSyn(k skey, s *session, seg *link.Seg) {
	if s == nil {
		w.accept(k, seg)
		return
	}
	if s.phase == phSyn {
		// Повтор SYN в незавершённую сессию — обычное дело: наш SYN-ACK потерялся.
		_ = s.conn.OnSynAgain(seg)
		return
	}
	w.h.stats.dropped.Add(1)
	if s.phase == phEst {
		s.roamCheck.CompareAndSwap(0, nowMS())
	}
	if ok, held := w.rlSynEst.Allow(nowMS(), wire.LogEveryMS); ok {
		w.h.logf("SYN в сессию, которая уже работает (%s:%d) — сессия не тронута, проверяю "+
			"пробой, жив ли её путь%s", ip4b(seg.SAddr), seg.SPort, wire.HeldSuffix(held))
	}
}

// accept — новая сессия на первом же поддельном SYN.
//
// Сессия создаётся БЕЗ всякой проверки: кто угодно из интернета может прислать SYN. Отсюда правило
// вытеснения в evict — неподтверждённые уходят первыми, иначе поток SYN с меняющихся портов выбивал
// бы из таблицы живые туннели, то есть стоил бы отказа в обслуживании ценой одного цикла на
// постороннем хосте. Живую сессию тот же SYN забрать не может вовсе, пока она не замолчала
// надолго; когда забирать нечего, приёма не происходит — это и есть отказ новому пиру.
func (w *worker) accept(k skey, seg *link.Seg) {
	if len(w.sess) >= w.sessMax {
		if !w.evict(evictIdleMS) {
			// Место занято живыми сессиями — новому пиру отказано. Строка нужна человеку:
			// снаружи это выглядит как «пир не подключается», а причина в ёмкости таблицы, и
			// догадаться о ней по молчанию нельзя.
			w.h.stats.dropped.Add(1)
			if ok, held := w.rlFull.Allow(nowMS(), wire.LogEveryMS); ok {
				w.h.logf("таблица сессий полна (%d), все заняты живыми — SYN от %s:%d отклонён%s",
					len(w.sess), ip4b(seg.SAddr), seg.SPort, wire.HeldSuffix(held))
			}
			return
		}
	}
	ns := w.newSession(seg)
	if ns == nil {
		return
	}
	w.sess[k] = ns
}

// newSession поднимает поддельное соединение по принятому SYN и отвечает SYN-ACK. Отдельной
// функцией от accept: сама сессия и её место в таблице воркера — разные решения, и второе зависит от
// того, была ли на этой четвёрке предыдущая.
func (w *worker) newSession(seg *link.Seg) *session {
	// Отвечаем С ТОГО адреса, НА КОТОРЫЙ пир написал: см. объяснение у link.OpenRawSend.
	raw, err := link.OpenRawSend(seg.SAddr, seg.DAddr)
	if err != nil {
		return nil
	}
	var isnBuf [4]byte
	if _, err := rand.Read(isnBuf[:]); err != nil {
		raw.Close()
		return nil
	}
	conn, err := link.Accept(raw, seg, uint16(w.h.opt.Conf.ListenPort),
		binary.BigEndian.Uint32(isnBuf[:]))
	if err != nil {
		raw.Close()
		return nil
	}
	bm := 2
	if w.h.opt.NoBatch {
		bm = 1
	}
	ns := &session{conn: conn, phase: phSyn, peer: -1, connID: -1}
	ns.batchMax.Store(int32(bm))
	return ns
}

// evict освобождает место под новую сессию: true — освободила.
//
// Порядок такой. Сперва самая давно молчавшая НЕподтверждённая, и без всякого срока: такая сессия
// заводится на первом же поддельном SYN, то есть кем угодно из интернета и без единой проверки, и
// цена ей — ноль. Именно этим хаб держит поток SYN с меняющихся портов: заваливая нас SYN'ами,
// посторонний вытесняет только свои же незавершённые сессии.
//
// Подтверждённую (phEst) можно забрать, только если она молчит дольше minIdleMS, то есть почти
// мертва (см. evictIdleMS). Раньше её забирали, как только неподтверждённых не осталось, — и при
// таблице, полной работающих туннелей, один посторонний SYN снимал живой туннель: пиру это стоило
// разрыва, нового рукопожатия и проверки пути, а нападающему — одного пакета.
//
// ЦЕНА НОВОГО ПРАВИЛА НАЗВАНА ПРЯМО: пока таблица занята живыми и молодыми сессиями, новый пир НЕ
// примется вовсе — accept вернётся ни с чем, и пир будет повторять SYN, пока место не появится
// (до минуты, если сессия и правда брошена; сразу, как только освободится любая). Это осознанный
// размен: отказ новому обратим повтором, а разрыв работающего туннеля — нет. Полная таблица одних
// лишь подтверждённых сессий сама по себе означает либо звезду больше настроенной (SessTotal
// вдвое больше законного максимума), либо застрявшие сессии — и то и другое чинится настройкой, а
// не выселением работающего пира.
func (w *worker) evict(minIdleMS int64) bool {
	var victim, raw *session
	var vk, rk skey
	var vIdle, rIdle int64
	for k, s := range w.sess {
		idle := s.idleMS()
		if s.phase != phEst {
			if raw == nil || idle > rIdle {
				raw, rk, rIdle = s, k, idle
			}
			continue
		}
		if victim == nil || idle > vIdle {
			victim, vk, vIdle = s, k, idle
		}
	}
	if raw != nil {
		w.free(rk, raw)
		return true
	}
	if victim != nil && vIdle > minIdleMS {
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
	// Ключи закрываются, а не просто забываются: за ядерным движком шифра стоят дескрипторы, и
	// сессия, ушедшая без этого, теряет их навсегда (см. noise.Keys.Close).
	s.tx.Close()
	s.rx.Close()
	s.tx, s.rx = nil, nil
	// Накопленное для прикрытия — чужие байты из интернета: держать их за освобождённой сессией
	// незачем, и горутина набора по обнулённой фазе сюда больше не вернётся.
	s.dialBuf = nil
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
	// Накопленное НЕ ОЧИЩАЕТСЯ до развилки «наш или нет» нарочно: дорожка неопознанного отдаёт
	// прикрытию именно присланное ЦЕЛИКОМ (см. startProxy), а очистка здесь оставляла ей последний
	// сегмент вместо всего Hello — то есть прикрытие отвечало на хвост записи TLS без её начала, а
	// имя из SNI не разбиралось вовсе. Тот же порядок и по той же причине в реализации на C
	// (xshub.c, hs_step). Очищается ниже, когда пир опознан и накопленное больше не нужно.
	full := s.hsBuf
	hs := &noise.HS{}
	if err := hs.ServerRead(w.h.opt.Sec.Priv, full, nil); err != nil {
		w.h.stats.strangers.Add(1)
		w.onStranger(k, s, seg, err)
		return
	}
	// Личность известна — ищем пира.
	found := w.h.findPeer(hs.PeerStatic)
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
	if !w.h.replayFresh(found, hs.Peer.Stamp) {
		if ok, held := w.rlStamp.Allow(nowMS(), wire.LogEveryMS); ok {
			w.h.logf("пир %d: метка времени старее прошлой — похоже на повтор%s",
				found+1, wire.HeldSuffix(held))
		}
		// Повтор записанного msg1 — тоже «не наш», и отвечать на него ИНАЧЕ, чем прочим
		// неопознанным, значит рассказывать прибору, что этот Hello он подобрал правильно.
		// Прежде эта ветка закрывала сессию молча, то есть отвечала «silent» при любой настройке
		// Decoy — единственная дорожка для чужих обходилась именно там, где чужой узнаваем.
		w.h.stats.strangers.Add(1)
		w.onStranger(k, s, seg, nil)
		return
	}
	s.peer = found
	s.hsBuf = nil // пир опознан: дорожке неопознанного накопленное больше не понадобится

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

	w.h.commitStamp(s.peer, stamp)
	// Одна сессия на соединение пира: новая заменяет прежнюю. Прежнюю мы здесь НЕ освобождаем —
	// она может принадлежать другому воркеру, и её запись лежит в ЕГО таблице. Вместо этого она
	// остаётся «смещённой» и её убирает свой владелец в своём же обслуживании: признак — привязка
	// пир→сессия указывает не на неё. Трафика она не несёт с этой секунды, потому что пир в неё
	// больше не отправляет.
	s.lastAuth.Store(nowMS())
	w.h.peerSess[s.peer][connID].Store(s)
	// Пир мог прийти с ДРУГОГО адреса: тогда его прежние соединения, скорее всего, ведут в точку,
	// которой больше нет, — и трафик в них уезжает в никуда. Проверяем это пробой, а не догадкой.
	w.roamStart(s)

	kind := "ChaCha20-Poly1305"
	if s.tx.Kind() == noise.AEADAES128 {
		kind = "AES-128-GCM"
	}
	w.h.logf("пир %s поднялся с %s:%d, MTU %d, шифр %s", conf.KeyFP(w.h.opt.Conf.Peers[s.peer].Pub),
		ip4b(k.addr), k.port, peerMTU, kind)
}

// roamStart — пир поднялся заново: остальным его соединениям ставится метка «проверься».
//
// ПРОВЕРЯЮТСЯ ВСЕ, А НЕ ТОЛЬКО ТЕ, ЧТО НА ДРУГОМ АДРЕСЕ. Первая версия сравнивала адреса и трогала
// лишь несовпавшие — и пропускала самый частый случай целиком. Пир, поднявшийся заново, приходит с
// НОВЫХ портов источника (порт выбирается случайно на каждое подключение), а адрес у него нередко
// тот же: перезапуск службы, выход из сна, смена настройки. Тогда слоты его прежних соединений
// оказываются осиротевшими при полностью совпадающем адресе, и по адресу их не отличить ничем.
//
// Свои слоты пир вытесняет сам: номер соединения он называет в подписанной части рукопожатия, и
// новая сессия заменяет прежнюю в том же слоте. Осиротевшими остаются те, которые он больше НЕ
// занимает — стало меньше ядер, другая настройка, другая сборка. Получателя хаб выбирает хешем
// потока среди живых слотов, поэтому такой слот означает не задержку, а потерю доли потоков целиком,
// и жил он до IdleMS, то есть три минуты.
//
// Разбираться с меткой будет ВЛАДЕЛЕЦ каждой такой сессии, в своём обслуживании: она лежит в его
// таблице, а не в нашей (у пира каждый порт источника достаётся своему воркеру фильтром в ядре). Мы
// только ставим метку — снимать сессию из чужой таблицы отсюда было бы гонкой в самом неудачном
// месте.
func (w *worker) roamStart(ns *session) {
	if ns.peer < 0 {
		return
	}
	now := nowMS()
	for c := 0; c < wire.ConnsMax; c++ {
		s := w.h.peerSess[ns.peer][c].Load()
		if s == nil || s == ns {
			continue
		}
		// Свежий подтверждённый трафик — доказательство живости, проверять нечего. Заодно это
		// защищает соседние соединения, которые поднялись минуту назад в том же залпе.
		if now-s.lastAuth.Load() < roamProbeMS {
			continue
		}
		s.roamCheck.CompareAndSwap(0, now)
	}
}

// onData — собрать записи из нагрузки сегмента, расшифровать и развести пакеты.
//
// ЦИКЛОМ, а не по одной записи на сегмент: ядро отдаёт в сырой сокет склеенное GRO, и записей в
// одной нагрузке бывает несколько (см. Reasm.Feed).
func (w *worker) onData(s *session, seg *link.Seg) {
	// Сборка записи, которая могла быть разрезана между сегментами. Она же предфильтр: сегмент, не
	// начинающийся с заголовка записи и не продолжающий начатую, отбрасывается до криптографии.
	s.reasm.FeedAll(seg.Seq, s.conn.ISNRX(), seg.Payload, func(body, hdr []byte, rel uint32) {
		w.onRecord(s, body, hdr, rel)
	})
}

// onRecord — одна собранная запись.
func (w *worker) onRecord(s *session, body, hdr []byte, rel uint32) {
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
	// Живость сессии отмечается ЗДЕСЬ, а не на приёме сегмента: доказательством служит сошедшийся
	// тег, а не сам факт, что в четвёрку кто-то написал. См. session.lastAuth.
	s.lastAuth.Store(nowMS())
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
	case wire.KindIPv4:
		// ПРЕДЕЛ ДЛИНЫ ОБЯЗАТЕЛЕН, и он не про разумность значения. Строка пересылки длиной
		// HdrRoom+MaxRecord+Tag, а copy() ниже УРЕЗАЕТ кадр молча — после чего sendTo берёт срез
		// row[HdrRoom : HdrRoom+plen+Tag] по урезанной длине, то есть на кадре длиннее строки
		// выходит за её границу: непойманная паника в горутине rxLoop убивает процесс хаба
		// целиком, а с ним все сессии звезды сразу («slice bounds out of range [:8269] with
		// capacity 8253»). Урезанный кадр и без паники не лучше — он уезжает пиру или в
		// устройство как пакет с длиной, не равной заявленной в его же заголовке IP.
		//
		// Законного кадра длиннее MTUDefault не бывает по построению: и клиент (client.go,
		// stream.go), и сам хаб (tunLoop) читают устройство в буфер ровно MTUDefault, а проба
		// пути ограничена тем же числом (wire.ProbeBuild). Значит это либо порча, либо чужая
		// реализация, и место ему в счётчике. Предел стоит там же, где в движке на C
		// (xshub.c: `if (pn > XS_MTU_DEF) return;`).
		if len(pt) > wire.MTUDefault {
			w.h.stats.dropped.Add(1)
			if ok, held := w.rlOver.Allow(nowMS(), wire.LogEveryMS); ok {
				w.h.logf("пир %s: кадр %d байт длиннее предела %d — отброшен%s",
					w.peerFP(s), len(pt), wire.MTUDefault, wire.HeldSuffix(held))
			}
			return
		}
		// Копия обязательна: пакет поедет дальше из строки с местом под заголовки впереди, а
		// пришёл он в приёмном буфере, где такого места нет.
		n := copy(w.row[wire.HdrRoom:], pt)
		w.route(s, w.row[wire.HdrRoom:wire.HdrRoom+n])
	case wire.KindIPv6:
		// IPv6 ОТБРАСЫВАЕТСЯ ЯВНО, а не по случайному отказу дальше. Маршрутизации IPv6 в хабе
		// нет: route разбирает любой кадр как IPv4 — адрес источника читается по смещению 12, а у
		// пакета IPv6 там лежит середина ЕГО адреса источника. Обычно такой кадр останавливает
		// проверка права на адрес, и «не поддерживается» выводилось из того, что она случайно
		// отказывает. Но пир, описанный в конфигурации, может подобрать эти байты так, чтобы они
		// попали в его разрешённый диапазон, — и тогда кадр IPv6 уезжает как пакет IPv4: с
		// уменьшением не того байта, пересчётом контрольной суммы, которой в IPv6 нет, и
		// подрезкой MSS не там. Пока маршрутизации нет, отказ обязан быть решением, а не
		// совпадением. Зеркало xshub.c (счётчик d_ipv6 и та же строка в журнале).
		w.h.stats.dropped.Add(1)
		if ok, held := w.rlIPv6.Allow(nowMS(), wire.LogEveryMS); ok {
			w.h.logf("пир %s: кадр IPv6 — маршрутизации IPv6 в хабе нет, отброшен%s",
				w.peerFP(s), wire.HeldSuffix(held))
		}
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
		s.batchMax.Store(1)
		s.coolUntil = nowMS() + reasmCooldownMS
		if ok, held := w.rlProbe.Allow(nowMS(), wire.LogEveryMS); ok {
			w.h.logf("пир не собрал %d записей — везу по одному кадру%s", n, wire.HeldSuffix(held))
		}
		return
	}
	// Итог согласования: пир проверил путь и называет рабочий размер. Берём минимум со своим
	// пределом — больше него мы всё равно не отправим.
	if mv := wire.MTUValue(pt); mv > 0 {
		// ПОТОЛОК ОДИН И ТОТ ЖЕ для числа из провода и для числа из конфигурации, и пропускать
		// его нельзя. Раньше конфигурация зажимала пира, а сама не зажималась ничем: MTU=1500 в
		// файле (то есть MTU КАНАЛА вместо MTU туннеля — обычная описка, конфигурация такое
		// принимает) плюс пир, назвавший столько же, давали maxSeg больше предельного сегмента, и
		// каждая разрезаемая запись отваливалась в «мал буфер под продолжение записи» — молча, в
		// счётчик отброшенных. Тот же класс, что нижняя граница ниже: число из провода проверяется
		// против СВОИХ пределов, а не только против другого числа из настроек.
		own := w.h.opt.Conf.MTU
		if own <= 0 || own > mtuCeil {
			own = mtuCeil
		}
		was := int(s.mtu.Load())
		// НИЖНЯЯ ГРАНИЦА ОБЯЗАТЕЛЬНА, и она не про разумность значения. По этому числу запись
		// режется на сегменты (sendTo → SendRecord), поэтому пир, назвавший MTU 1, заставляет хаб
		// резать каждую предельную запись на 374 сегмента — шестидесятикратное умножение
		// системных вызовов по своей же воле, и всё это по одному служебному кадру. Ниже MTUFloor
		// не опускается и сам пробой пути, значит меньшее значение — не «узкий путь», а
		// непроверенное число из провода. Зеркало xshub.c (XS_MTU_FLOOR).
		if mv < wire.MTUFloor {
			prev := was
			if prev == 0 {
				prev = wire.MTUDefault
			}
			if ok, held := w.rlMTU.Allow(nowMS(), wire.LogEveryMS); ok {
				w.h.logf("пир %s: назвал MTU %d — ниже предела %d, оставляю прежний %d%s",
					w.peerFP(s), mv, wire.MTUFloor, prev, wire.HeldSuffix(held))
			}
			return
		}
		agreed := mv
		if own < mv {
			agreed = own
		}
		s.mtu.Store(int32(agreed))
		// Печатаем только ИЗМЕНЕНИЕ: кадр приходит после каждого пробоя пира, то есть раз в две
		// минуты на каждого, и строка «согласован тот же MTU» через год работы звезды из тридцати
		// пиров — это четверть миллиона строк ни о чём.
		if agreed != was && s.peer >= 0 {
			w.h.logf("пир %s: согласован MTU %d", conf.KeyFP(w.h.opt.Conf.Peers[s.peer].Pub), agreed)
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
	to := w.h.router.Lookup(dst, &w.rcache)
	if to >= 0 && to != from.peer {
		if d := w.h.pick(to, pt); d != nil {
			// Пир↔пир: уменьшаем TTL (иначе петля в звезде живёт вечно) и шифруем В ТОЙ ЖЕ строке.
			if !route.TTLDec(pt) {
				return
			}
			// Подрезка MSS по УЗКОМУ МЕСТУ пути пир→пир, а это МИНИМУМ из MTU обеих сессий.
			//
			// Только по получателю недостаточно, и это не перестраховка. MSS в SYN объявляет то,
			// что отправитель готов ПРИНИМАТЬ, то есть ограничивает размер сегментов, которые
			// вторая сторона будет слать ОБРАТНО; а обратный путь идёт через ОБА тоннеля. Пусть у
			// пира-отправителя MTU 1420, у получателя 1380, хаб шире обоих (то есть НЕ узкое
			// место): клампинг только по 1380 оставил бы обратному потоку MSS под 1420, и его
			// полноразмерные сегменты не влезали бы в тоннель отправителя — те самые «большие
			// пакеты молча пропадают». Кроме хаба этот минимум посчитать некому: пиры друг о друге
			// ничего не знают. Когда узкое место сам хаб (как при хабе 1300 против пиров 1420 и
			// 1380), согласование и так опускает обе сессии до 1300, и минимум даёт то же число.
			if clamp := minMTU(int(from.mtu.Load()), int(d.mtu.Load())); clamp > 0 {
				route.MSSClamp(pt, clamp)
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
	// Свой кэш маршрута: эта горутина не имеет права трогать w.rcache, он принадлежит приёму.
	var rc route.Cache
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
			if len(frames) > 0 && (len(frames) >= int(dst.batchMax.Load()) ||
				total+2+wire.MTUDefault > wire.MaxPlain) {
				break
			}
			n, err := w.dev.Read(slab[used : used+wire.MTUDefault])
			if err != nil || n <= 20 {
				break
			}
			pkt := slab[used : used+n]
			to := w.h.router.Lookup(binary.BigEndian.Uint32(pkt[16:20]), &rc)
			var d *session
			if to >= 0 {
				d = w.h.pick(to, pkt)
			}
			if d == nil {
				continue // нет живого соединения к этому пиру — отбросить, память не тратим
			}
			// Подрезка по значению, действующему НА ЭТОТ КАДР: согласование могло сдвинуть его
			// прямо сейчас, и каждый кадр обязан быть подрезан тем, что в силе в его миг.
			if mtu := int(d.mtu.Load()); mtu > 0 {
				route.MSSClamp(pkt, mtu)
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
	return total+2+next > wire.MaxPlain
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
	mtu := int(d.mtu.Load())
	if mtu <= 0 {
		mtu = mtuCeil
	}
	maxSeg := mtu + wire.Overhead - 40
	// Буфер продолжения — СЕССИИ, а не воркера: он защищён этим самым замком, и держать его у
	// воркера значило бы отдать один буфер под два разных замка. Почему лениво и почему это
	// единственное верное место — в шапке поля session.cont.
	if d.cont == nil {
		d.cont = make([]byte, contLen)
	}
	err := d.conn.SendRecord(row, wire.RecHdr+plen+wire.Tag, maxSeg, d.cont, func(rel uint32) error {
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

// maintain — обслуживание СВОИХ сессий: уборка, keepalive, подтверждения, проба переезда.
func (w *worker) maintain() {
	for k, s := range w.sess {
		// Проба переезда: пир поднялся с другого адреса, и надо выяснить, ведёт ли ЭТА сессия ещё
		// куда-нибудь. Пустая запись уходит и должна вернуться подтверждённым ответом; молчание
		// после трёх попыток означает, что точка мертва, и слот освобождается немедленно.
		//
		// Освободить надо ИМЕННО привязку пир→сессия, и в первую очередь её: получателя выбирает
		// хеш потока среди живых соединений пира, поэтому мёртвый слот означает не задержку, а
		// потерю доли потоков целиком. Саму сессию доуберёт обычная уборка ниже.
		if s.roamCheck.Load() != 0 && s.phase == phEst {
			now := nowMS()
			// ОТВЕТОМ СЧИТАЕТСЯ ЛЮБОЙ ПРИНЯТЫЙ СЕГМЕНТ, а не только подтверждённая запись, и это
			// не послабление, а единственно возможная мерка.
			//
			// На пустую запись пир отвечает голым подтверждением TCP через AckMS (40 мс), и это
			// ровно то, что доказывает живость пути. Отвечать ЗАПИСЬЮ ему нечем: кадра «ответь мне»
			// в протоколе нет, а своя пустая запись уйдёт от него только по его же keepalive, то
			// есть через секунды. Мерить пробу подтверждённым трафиком значило бы объявлять мёртвым
			// живое соединение на покое.
			//
			// Чем это слабее: посторонний, бьющий в четвёрку, может пробу «пройти» за пира. Но
			// ровно так же он мог бы держать сессию живой против DeadMS и до этой правки, то есть
			// новой возможности здесь не появилось. А уборка по простою — та считается по
			// подтверждённому трафику, см. idleMS.
			lastRX := now - s.conn.Idle()
			switch {
			case s.roamSent > 0 && lastRX >= s.roamFirst:
				// Ответила — путь жив. Счётчики обнуляются оба: следующая проба обязана начаться с
				// первой попытки, иначе она снимет сессию, не спросив.
				s.roamCheck.Store(0)
				s.roamSent, s.roamNext, s.roamFirst = 0, 0, 0
			case s.roamSent >= roamProbes && now >= s.roamNext:
				w.h.logf("пир %s: точка %s:%d не ответила на пробу — снимаю её слот сразу, "+
					"без ожидания простоя", w.peerFP(s), ip4b(k.addr), k.port)
				if s.peer >= 0 && s.connID >= 0 {
					w.h.peerSess[s.peer][s.connID].CompareAndSwap(s, nil)
				}
				s.roamCheck.Store(0)
				w.free(k, s)
				continue
			case now >= s.roamNext:
				if s.roamSent == 0 {
					s.roamFirst = now
				}
				w.sendTo(s, w.row, 0)
				s.roamSent++
				s.roamNext = now + roamProbeMS
			}
		}
		// Сессию, помеченную к уборке (например, прикрытие закрылось), убирает ВЛАДЕЛЕЦ: таблица
		// его личная.
		if s.dead.Load() {
			// Под замком: соединение к прикрытию ставит ГОРУТИНА ЗВОНКА (I-126), то есть не
			// владелец, и читать это поле без замка стало нельзя.
			s.mu.Lock()
			up := s.up
			s.up = nil
			s.mu.Unlock()
			if up != nil {
				up.Close()
			}
			w.free(k, s)
			continue
		}
		// Простой считается по ПОДТВЕРЖДЁННОМУ трафику, а не по любому принятому сегменту.
		//
		// Разница не теоретическая: на публичный порт хаба сыплется сканерный шум, и время
		// последнего приёма в соединении обновляет каждый такой сегмент. Пока уборка смотрела на
		// него, сессия, в которую пир давно не пишет, могла жить сколько угодно — достаточно, чтобы
		// кто-то посторонний бил в её четвёрку. Слот в наборе пира она при этом занимала, то есть
		// часть его трафика уезжала в никуда. Незавершённые сессии считаются по-прежнему: у них
		// подтверждённого трафика ещё не было по построению.
		if s.idleMS() > IdleMS {
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
			if !w.h.opt.NoBatch && now >= s.coolUntil && now-s.lastGrow >= reasmGrowMS {
				if bm := int(s.batchMax.Load()); bm < wire.BatchFramesMax {
					bm *= 2
					if bm > wire.BatchFramesMax {
						bm = wire.BatchFramesMax
					}
					s.batchMax.Store(int32(bm))
					s.lastGrow = now
				}
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

// offloadLine — строка про разгрузку сегментации устройства. Печатается ВСЕГДА: разница в скорости
// здесь измеряется разами (замер: 3920 нс на пакет против 269 нс), поэтому «почему медленно» не
// должно требовать догадок. Проверка через утверждение типа, а не через метод интерфейса: разгрузка
// есть только на Linux, и знание об этом обязано остаться в пакете tun.
func offloadLine(d tun.Device) string {
	o, ok := d.(interface{ Offload() (bool, string) })
	if !ok {
		return "разгрузка сегментации: нет на этой системе"
	}
	on, why := o.Offload()
	if on {
		return "разгрузка сегментации устройства: включена (склейка пакетов в супер-кадр)"
	}
	return "разгрузка сегментации устройства: НЕТ (" + why + ") — путь по одному пакету"
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
			if s == nil {
				continue
			}
			mtu := int(s.mtu.Load())
			if mtu <= 0 {
				continue
			}
			if best == 0 || mtu < best {
				best = mtu
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

// minMTU — узкое место из двух согласованных MTU. Ноль означает «ещё не согласован» и в
// минимуме не участвует: клампить не по чему, пока сторона не назвала свой размер.
func minMTU(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

// peerFP — отпечаток ключа пира для журнала, или «?», пока пир не опознан. Отдельной функцией
// потому, что строки про отброшенные кадры печатаются из нескольких мест, а индекс пира в них
// может быть ещё не заполнен: обращение к Peers[-1] стоило бы паники ровно там, где мы отбиваем
// чужой пакет.
func (w *worker) peerFP(s *session) string {
	if s == nil || s.peer < 0 || s.peer >= len(w.h.opt.Conf.Peers) {
		return "?"
	}
	return conf.KeyFP(w.h.opt.Conf.Peers[s.peer].Pub)
}

// idleMS — сколько сессия молчит. Для ПОДТВЕРЖДЁННОЙ считается по последнему кадру, у которого
// сошёлся тег (session.lastAuth); для остальных — по последнему принятому сегменту, потому что
// подтверждённого трафика у них ещё не было.
func (s *session) idleMS() int64 {
	if s.phase == phEst {
		if t := s.lastAuth.Load(); t != 0 {
			return nowMS() - t
		}
	}
	return s.conn.Idle()
}

func nowMS() int64 { return time.Now().UnixNano() / int64(time.Millisecond) }

func ip4str(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func ip4b(a [4]byte) string { return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3]) }
