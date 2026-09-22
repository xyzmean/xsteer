package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/xyzmean/xsteer/link"
	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/route"
	"github.com/xyzmean/xsteer/tun"
	"github.com/xyzmean/xsteer/wire"
)

// Режим потока: записи по НАСТОЯЩЕМУ соединению TCP вместо поддельного.
//
// Зачем он есть — в шапке wire/stream.go: на Windows поддельный TCP невозможен без драйвера, а
// заодно настоящий стек бесплатно и точно делает всё, что мы изображали руками. Цена — внешний
// транспорт становится надёжным, то есть внутренний TCP едет поверх TCP; насколько это дорого,
// решает замер (tests/loss.sh), а не спор.
//
// Чего в этом режиме НЕТ и почему:
//
//   - проб пути. Внешним MTU распоряжается ядро (оно само делает обнаружение MTU пути и режет
//     поток на сегменты), а размер записи ему безразличен. Внутренний MTU берётся из рукопожатия
//     как минимум пределов сторон — то есть первая ступень согласования остаётся, вторая теряет
//     смысл;
//   - обратной связи по сборке. Разрезанных записей здесь не бывает: поток доставляет всё и по
//     порядку, поэтому и пачка всегда полного размера;
//   - окна, PSH, голых подтверждений и прочего изображения стека. Всё это делает настоящий стек.

// streamProbeMS — как часто в режиме потока уходит проба живости. Две секунды: сторож маршрута
// считает канал живым, пока кадры от хаба не старше пяти, так что три пропущенные подряд пробы —
// уже не случайность.
const streamProbeMS = 2000

// streamStallGapMS — с какого перерыва между проверками сторожа мы считаем, что не работали МЫ, а
// не путь. То же число и тот же смысл, что у link.stallGapMS и XSC_STALL_GAP_MS в C: исправный
// сторож проверяет раз в streamWatchMS, и перерыв в секунду означает, что процессор нам не давали
// (на телефоне — дремота, в которой процесс заморожен целиком).
const streamStallGapMS = 1000

// streamWatchMS — как часто сторож потока смотрит на тишину. Тот же шаг, что у ожидания устройства
// в streamOut: точнее двухсот миллисекунд порог в восемь секунд знать незачем, а лишние
// пробуждения на телефоне стоят батареи.
const streamWatchMS = 200

// streamLive — времена последней отправки и последнего приёма ОДНОЙ сессии потока, в миллисекундах.
// Пишут их горутины отправки и приёма, читает сторож.
//
// Отдельно от c.stats.lastRx, и это не дублирование: тот общий на все соединения клиента, и живое
// соседнее соединение скрывало бы мёртвое.
type streamLive struct {
	tx, rx atomic.Int64
}

// streamJudge — решение «путь мёртв» для потока: мы отправили ПОСЛЕ последнего приёма, и тишина
// с тех пор дольше link.DeadMS.
//
// Форма та же, что у link.Conn.tick и xs_conn_tick, и расхождение в ней означало бы, что один и тот
// же пир на одном транспорте живёт, а на другом переподнимается. Из тишины вычитается не наша
// тишина двух видов: нас не исполняли (перерыв между проверками дольше streamStallGapMS) и нам
// было нечего сказать (tx <= rx). Запас обнуляется на каждом новом приёме.
type streamJudge struct {
	tickAt, stall, rxSeen int64
}

func (j *streamJudge) dead(now, tx, rx int64) bool {
	if rx != j.rxSeen {
		j.rxSeen = rx
		j.stall = 0
	}
	if j.tickAt != 0 {
		if gap := now - j.tickAt; gap > streamStallGapMS || tx <= rx {
			j.stall += gap
		}
	}
	j.tickAt = now
	return tx > rx && now-rx-j.stall > link.DeadMS
}

// streamSession поднимает соединение в режиме потока и работает до его обрыва.
func (c *Client) streamSession(ctx context.Context, id int, dev tun.Device) error {
	// Подписка на смену сети — ДО набора номера, как и в worker: смена, случившаяся во время
	// подключения или рукопожатия, тоже означает, что этот сокет открыт в прежней сети.
	netCh := c.netChanged()
	addr := net.JoinHostPort(c.opt.Conf.Peers[0].Endpoint, fmt.Sprint(c.streamPort()))
	// Control привязывает СВОЙ сокет к физическому интерфейсу, чтобы соединение к хабу не ушло в
	// туннель (см. tun/pin_windows.go). Там же объяснено, почему это лучше маршрута-обхода: чужой
	// трафик к адресу хаба — ssh на тот же сервер, например — остаётся в туннеле.
	d := net.Dialer{Timeout: 10 * time.Second, Control: c.dialControl}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer nc.Close()
	if tc, ok := nc.(*net.TCPConn); ok {
		// Без задержки Нейгла: мелкий кадр (внутреннее подтверждение, проба, keepalive) не должен
		// ждать, пока наберётся сегмент. Задержка здесь стоила бы кругов внутреннему TCP.
		_ = tc.SetNoDelay(true)
		// Размеры буферов НЕ задаём: явный setsockopt отключает автоподстройку и режется по
		// net.core.{r,w}mem_max. Объяснение с числами — в шапке wire/stream.go.
	}
	c.logf("соединение %d: поток к %s открыт", id, addr)

	st := wire.NewStream(nc)
	hs := &noise.HS{}
	defer hs.Wipe()

	mtuSay := wire.MTUDefault
	if c.opt.Conf.MTU > 0 && c.opt.Conf.MTU < mtuSay {
		mtuSay = c.opt.Conf.MTU
	}
	// Само рукопожатие — общее с поддельным TCP (см. doClientHandshake). Здесь только рамка потока:
	// Hello уходит одним вызовом (резать его на сегменты — дело ядра), ответ собирается запись за
	// записью. Крышка по времени на всё рукопожатие: чтения потока блокирующие и про контекст не
	// знают.
	_ = nc.SetDeadline(time.Now().Add(15 * time.Second))
	hres, err := c.doClientHandshake(hs, &streamHello{st: st}, mtuSay, id, true)
	if err != nil {
		return err
	}
	_ = nc.SetDeadline(time.Time{})
	tx, rx := hres.tx, hres.rx
	// Отсчёт тишины — от рукопожатия: ответ хаба на него и есть последний приём. Так же в C
	// (stream_rx = handshake_at).
	live := &streamLive{}
	live.rx.Store(nowMS())
	defer func() { tx.Close(); rx.Close() }()

	// Согласование MTU: первая ступень та же — минимум пределов сторон. Второй (проб пути) в
	// потоке нет: сегментацией распоряжается ядро.
	mtu := mtuSay
	if p := int(hres.peer.MTU); p > 0 && p < mtu {
		mtu = p
	}
	// Ратчет эпох включается ДО первой записи данных и на обоих направлениях: номер эпохи
	// считается из смещения, и сторона, включившая его позже, разошлась бы с другой (см.
	// noise/epoch.go). На проводе от этого не меняется ни один байт.
	tx.EnableEpochs()
	rx.EnableEpochs()
	c.logf("соединение %d: рукопожатие прошло, шифр %s, MTU %d (поток), ключи меняются каждые %d МиБ",
		id, tx.Kind(), mtu, noise.EpochBytes>>20)
	if id == 0 {
		c.applyMTU(dev, dev.Name(), mtu, "согласовано в рукопожатии (поток)")
	}
	c.mtuPub.Store(int64(mtu))
	c.stats.up.Add(1)
	c.stats.lastHandshake.Store(time.Now().Unix())
	defer c.stats.up.Add(-1)

	// Сообщаем хабу рабочий размер тем же служебным кадром, что и в поддельном TCP: по нему он
	// подрезает MSS обратного трафика для ЭТОЙ сессии.
	{
		row := make([]byte, wire.HdrRoom+8+wire.Tag)
		if n := wire.MTUBuild(row[wire.HdrRoom:wire.HdrRoom+8], mtu); n > 0 {
			if c.streamSend(st, tx, row, n) == nil {
				live.tx.Store(nowMS())
			}
		}
	}

	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		<-sctx.Done()
		nc.Close() // разбудить чтение: у потока нет опроса с таймаутом
	}()

	done := make(chan error, 3)
	go func() { done <- c.streamIn(sctx, id, st, rx, dev, live) }()
	go func() { done <- c.streamOut(sctx, id, st, tx, dev, mtu, live) }()
	go func() { done <- c.streamWatch(sctx, netCh, live) }()
	err = <-done
	stop()
	<-done
	<-done
	return err
}

// streamWatch — сторож сессии потока: возвращает причину, по которой её надо оборвать, или
// ошибку контекста, когда сессия кончилась сама.
//
// СМЕНА ПОКОЛЕНИЯ СЕТИ. У поддельного TCP её читает timeLoop, а у потока долго не читал никто —
// и на телефоне это был единственный режим. Сессия потока висит в блокирующем ReadRecord без
// срока: после пробуждения (NAT и хаб уже забыли соединение) или смены Wi-Fi на LTE сокет,
// открытый в прежней сети, «жив» для ядра, пробы ложатся в его буфер, а туннель не несёт ничего,
// пока ядро не сдастся по повторам — при tcp_retries2 = 15 это около пятнадцати минут. Сигнал о
// смене был (NetChanged с платформы, netlink на Linux), но до потока он не доходил.
//
// Обрыв делается возвратом отсюда: streamSession отменяет контекст сессии, и горутина-будильник
// закрывает сокет — это единственное, что разблокирует ReadRecord и застрявшую запись. Причина
// уходит в done ПЕРВОЙ (раньше ошибок чтения на закрытом сокете), поэтому в журнал попадает она,
// а не «use of closed network connection».
//
// МЁРТВЫЙ ХАБ (I-134). Сам поток TCP о смерти хаба узнаёт через минуты: пока ядро не исчерпало
// повторы, соединение для него живо. У реализации на C правило «шлём, а в ответ тишина дольше
// порога» стояло в цикле потока с самого начала, у пира на Go — только в поддельном TCP
// (link.Conn.Tick). Решение — streamJudge, порог тот же link.DeadMS. Проверка живёт ЗДЕСЬ, а не в
// streamOut, потому что к мёртвому хабу запись застревает: буфер сокета полон, WriteRecord
// блокирует, и цикл отправки не дошёл бы до проверки никогда.
func (c *Client) streamWatch(ctx context.Context, netCh <-chan struct{}, live *streamLive) error {
	t := time.NewTicker(streamWatchMS * time.Millisecond)
	defer t.Stop()
	var j streamJudge
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-netCh:
			return errors.New("сеть изменилась — поднимаю соединение заново")
		case <-t.C:
		}
		if j.dead(nowMS(), live.tx.Load(), live.rx.Load()) {
			return fmt.Errorf("поток молчит %d мс при активной отправке — поднимаю заново",
				link.DeadMS)
		}
	}
}

// streamOut: TUN → поток. Пачка собирается так же, как в поддельном TCP, но резать запись на
// сегменты не нужно — это работа ядра.
func (c *Client) streamOut(ctx context.Context, id int, st *wire.Stream, tx *noise.Keys,
	dev tun.Device, mtu int, live *streamLive) error {
	row := make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag)
	slab := make([]byte, wire.BatchFramesMax*wire.MTUDefault)
	frames := make([][]byte, 0, wire.BatchFramesMax)
	keep := int64(c.opt.Conf.Peers[0].Keepalive) * 1000
	last := nowMS()
	lastProbe := int64(0)
	for ctx.Err() == nil {
		// Проба живости. В потоке согласовывать MTU нечем — сегментацией распоряжается ядро, — но
		// проба нужна не ради размера: хаб отвечает на неё эхом, и это ЕДИНСТВЕННЫЙ признак того,
		// что канал несёт трафик в обратную сторону. Без него полный туннель не отличил бы
		// работающий хаб от хаба, который принимает всё и не отвечает ничем, — а разница между
		// ними для человека это разница между «VPN» и «нет интернета».
		//
		// Кадр крохотный (три байта) и уходит раз в две секунды: столько же стоит один keepalive,
		// а даёт сторожу маршрута непрерывную картину.
		//
		// ПО ВРЕМЕНИ, А НЕ ПО ПРОСТОЮ УСТРОЙСТВА (I-134). Прежде проба уходила только из ветки
		// «устройство молчит», и на односторонней отдаче — закачка наверх, устройство читаемо
		// всегда — проб не было вовсе: хаб не присылал эха, сторож маршрута слеп, а правило
		// «тишина при активной отправке» (streamWatch) оборвало бы живую сессию. В C она уходит
		// из тела цикла безусловно — теперь и здесь.
		if now := nowMS(); now-lastProbe >= streamProbeMS {
			if n, ok := wire.ProbeBuild(row[wire.HdrRoom:wire.HdrRoom+wire.ProbeMin], wire.ProbeMin); ok {
				if err := c.streamSend(st, tx, row, n); err != nil {
					return err
				}
				last = now
				live.tx.Store(now)
			}
			lastProbe = now
		}
		ok, err := dev.WaitRead(200 * time.Millisecond)
		if err != nil {
			return err
		}
		if !ok {
			// Keepalive: пустая запись с разбросом интервала. Настоящий TCP держит соединение
			// своими средствами лишь через часы, а отображение NAT живёт минуты.
			if keep > 0 && nowMS()-last >= keep {
				if err := c.streamSend(st, tx, row, 0); err != nil {
					return err
				}
				last = nowMS()
				live.tx.Store(last)
			}
			continue
		}
		frames = frames[:0]
		used, total := 0, wire.BatchHdr
		// --no-batch обязан действовать И в потоке. Раньше ключ здесь просто не читался: разбор
		// его принимал, справка обещала «везу по одному кадру», а поток всё равно собирал пачки.
		// Ключ, который молча ничего не делает, хуже отсутствующего — человек считает, что
		// настроил совместимость с хабом, который пачек не понимает, и ищет причину где угодно,
		// только не в нём.
		maxFrames := wire.BatchFramesMax
		if c.opt.NoBatch {
			maxFrames = 1
		}
		for len(frames) < maxFrames {
			if len(frames) > 0 && total+2+mtu > wire.MaxPlain {
				break
			}
			n, err := dev.Read(slab[used : used+wire.MTUDefault])
			if errors.Is(err, tun.ErrAgain) {
				break
			}
			if err != nil {
				return err
			}
			if n <= 0 {
				break
			}
			f := slab[used : used+n]
			route.MSSClamp(f, mtu)
			frames = append(frames, f)
			used += n
			total += 2 + n
		}
		if len(frames) == 0 {
			continue
		}
		var pn int
		if len(frames) == 1 {
			pn = copy(row[wire.HdrRoom:], frames[0])
		} else {
			pn = wire.BatchBuild(row[wire.HdrRoom:], frames)
			if pn == 0 {
				continue
			}
		}
		if err := c.streamSend(st, tx, row, pn); err != nil {
			return err
		}
		last = nowMS()
		live.tx.Store(last)
		c.stats.txPkts.Add(uint64(len(frames)))
		for _, f := range frames {
			c.stats.txBytes.Add(uint64(len(f)))
		}
		// Ретайра по объёму здесь БОЛЬШЕ НЕТ, и это осознанно. Он существовал ровно для того,
		// чтобы 32-битное смещение не завернулось и не повторило nonce; теперь смещение
		// 64-битное (см. шапку wire.Stream), заворот недостижим, а ронять живое соединение
		// каждый гигабайт — ощутимая беда: внутренние TCP-сессии рвутся на ровном месте.
		//
		// Периодическая смена ключей ради прямой секретности — отдельная задача, и делать её
		// надо тоже без разрыва: эпохами, как в veil (epoch.Advance ратчетит корень, номер
		// эпохи входит в контекст KDF, рукопожатие не повторяется).
	}
	return ctx.Err()
}

// streamSend шифрует и отправляет одну запись.
func (c *Client) streamSend(st *wire.Stream, tx *noise.Keys, row []byte, n int) error {
	rec := row[wire.HdrRoom-wire.RecHdr : wire.HdrRoom]
	return st.WriteRecord(row, wire.RecHdr+n+wire.Tag, func(rel uint64) error {
		if err := wire.RecBuild(rec, n+wire.Tag); err != nil {
			return err
		}
		_, err := tx.Seal(row[wire.HdrRoom:wire.HdrRoom+n+wire.Tag], n, rec, rel)
		return err
	})
}

// streamIn: поток → TUN.
func (c *Client) streamIn(ctx context.Context, id int, st *wire.Stream, rx *noise.Keys,
	dev tun.Device, live *streamLive) error {
	s := &sess{} // нужен onFrame: в потоке из него используется только запись в устройство
	for ctx.Err() == nil {
		body, hdr, rel, err := st.ReadRecord()
		if err != nil {
			return err
		}
		pt, err := rx.Open(body, hdr, rel)
		if err != nil {
			// В потоке испорченная запись означает, что дальше читать нечего: границы следующей
			// известны только из длины, которой мы уже не верим.
			return fmt.Errorf("запись не расшифровалась: %w", err)
		}
		// Любая расшифрованная запись — ответ хаба, включая keepalive и эхо на пробу.
		live.rx.Store(nowMS())
		if len(pt) > 0 && pt[0] == wire.CtlBatch {
			if !wire.BatchIter(pt, func(f []byte) { c.onFrame(s, id, f, dev) }) {
				c.stats.dropped.Add(1)
			}
		} else {
			c.onFrame(s, id, pt, dev)
		}
		// ВСПЛЕСК КОНЧИЛСЯ ЗДЕСЬ, и устройству надо об этом сказать.
		//
		// Одна запись — один всплеск: следующая придёт из ReadRecord, который блокирует, то есть
		// ждать её, держа пакеты в буфере устройства, можно сколько угодно долго. Накапливающее
		// устройство без этого вызова положило бы последний пакет всплеска в буфер и оставило бы
		// его там до следующей записи — то есть навсегда, если человек открыл одну страницу и
		// замолчал. Быстрый путь (поддельный TCP) звал Flush с самого начала, а этот — нет, и
		// работало это лишь потому, что режим потока пока применялся там, где накопления нет.
		//
		// Там, где Flush ничего не делает, вызов ничего и не стоит.
		_ = dev.Flush()
	}
	return ctx.Err()
}

func (c *Client) streamPort() int {
	if c.opt.StreamPort > 0 {
		return c.opt.StreamPort
	}
	return c.hub.port
}

var _ = link.PSH
