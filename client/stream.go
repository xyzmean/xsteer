package client

import (
	"context"
	"errors"
	"fmt"
	"net"
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

// streamSession поднимает соединение в режиме потока и работает до его обрыва.
func (c *Client) streamSession(ctx context.Context, id int, dev tun.Device) error {
	addr := net.JoinHostPort(c.opt.Conf.Peers[0].Endpoint, fmt.Sprint(c.streamPort()))
	d := net.Dialer{Timeout: 10 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer nc.Close()
	if tc, ok := nc.(*net.TCPConn); ok {
		// Без задержки Нейгла: мелкий кадр (внутреннее подтверждение, проба, keepalive) не должен
		// ждать, пока наберётся сегмент. Задержка здесь стоила бы кругов внутреннему TCP.
		_ = tc.SetNoDelay(true)
	}
	c.logf("соединение %d: поток к %s открыт", id, addr)

	st := wire.NewStream(nc)
	hs := &noise.HS{}
	defer hs.Wipe()

	mtuSay := wire.MTUDefault
	if c.opt.Conf.MTU > 0 && c.opt.Conf.MTU < mtuSay {
		mtuSay = c.opt.Conf.MTU
	}
	hello, err := hs.ClientHello(c.opt.Sec.Priv, c.hub.pub, c.opt.Conf.SNI, mtuSay, id,
		c.opt.AESPreferred, true, nil)
	if err != nil {
		return fmt.Errorf("рукопожатие не собралось: %w", err)
	}
	// Hello уходит одним вызовом: резать его на сегменты — дело ядра, и оно делает это так же, как
	// у браузера, у которого Hello тоже не влезает в один сегмент.
	_ = nc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := st.WriteRaw(hello); err != nil {
		return err
	}

	// Ответ хаба собирается ЗАПИСЬ ЗА ЗАПИСЬЮ до конца: разбор вбирает прочитанное в транскрипт, и
	// вызвать его на неполном ответе значило бы посчитать часть дважды. Конец узнаём по последней
	// записи — подтверждению: у неё известная длина.
	acc := make([]byte, 0, 4096)
	for i := 0; i < 8; i++ {
		var hdr [wire.RecHdr]byte
		if err := st.ReadFull(hdr[:]); err != nil {
			return fmt.Errorf("хаб не ответил на рукопожатие: %w", err)
		}
		n := int(hdr[3])<<8 | int(hdr[4])
		if n < 1 || n > wire.MaxRecord {
			return fmt.Errorf("хаб ответил не тем: запись длиной %d", n)
		}
		body := make([]byte, n)
		if err := st.ReadFull(body); err != nil {
			return err
		}
		acc = append(acc, hdr[:]...)
		acc = append(acc, body...)
		// Подтверждение — запись данных ровно этой длины; она в ответе последняя.
		if hdr[0] == 0x17 && n == noise.FinBody {
			break
		}
	}
	tx, rx, _, err := hs.ClientFinish(acc)
	if err != nil {
		return fmt.Errorf("хаб не признал нас или ответил не тем: %w", err)
	}
	confirm, err := hs.ClientConfirm(tx)
	if err != nil {
		return err
	}
	if err := st.WriteRaw(confirm); err != nil {
		return err
	}
	_ = nc.SetDeadline(time.Time{})

	// Согласование MTU: первая ступень та же — минимум пределов сторон. Второй (проб пути) в
	// потоке нет: сегментацией распоряжается ядро.
	mtu := mtuSay
	if p := int(hs.Peer.MTU); p > 0 && p < mtu {
		mtu = p
	}
	c.logf("соединение %d: рукопожатие прошло, шифр %s, MTU %d (поток)", id, tx.Kind(), mtu)
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
			_ = c.streamSend(st, tx, row, n)
		}
	}

	sctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		<-sctx.Done()
		nc.Close() // разбудить чтение: у потока нет опроса с таймаутом
	}()

	done := make(chan error, 2)
	go func() { done <- c.streamIn(sctx, id, st, rx, dev) }()
	go func() { done <- c.streamOut(sctx, id, st, tx, dev, mtu) }()
	err = <-done
	stop()
	<-done
	return err
}

// streamOut: TUN → поток. Пачка собирается так же, как в поддельном TCP, но резать запись на
// сегменты не нужно — это работа ядра.
func (c *Client) streamOut(ctx context.Context, id int, st *wire.Stream, tx *noise.Keys,
	dev tun.Device, mtu int) error {
	row := make([]byte, wire.HdrRoom+wire.MaxRecord+wire.Tag)
	slab := make([]byte, wire.BatchFramesMax*wire.MTUDefault)
	frames := make([][]byte, 0, wire.BatchFramesMax)
	keep := int64(c.opt.Conf.Peers[0].Keepalive) * 1000
	last := nowMS()
	for ctx.Err() == nil {
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
			}
			continue
		}
		frames = frames[:0]
		used, total := 0, wire.BatchHdr
		for len(frames) < wire.BatchFramesMax {
			if len(frames) > 0 && total+2+mtu > wire.MaxRecord {
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
		c.stats.txPkts.Add(uint64(len(frames)))
		for _, f := range frames {
			c.stats.txBytes.Add(uint64(len(f)))
		}
		// Ретайр по объёму остаётся: смещение в потоке — те же 32 бита, и заворот означал бы
		// повтор nonce.
		if st.TxNext() >= wire.RelRetire {
			c.logf("соединение %d: смена ключей — поднимаю поток заново", id)
			return nil
		}
	}
	return ctx.Err()
}

// streamSend шифрует и отправляет одну запись.
func (c *Client) streamSend(st *wire.Stream, tx *noise.Keys, row []byte, n int) error {
	rec := row[wire.HdrRoom-wire.RecHdr : wire.HdrRoom]
	return st.WriteRecord(row, wire.RecHdr+n+wire.Tag, func(rel uint32) error {
		if err := wire.RecBuild(rec, n+wire.Tag); err != nil {
			return err
		}
		_, err := tx.Seal(row[wire.HdrRoom:wire.HdrRoom+n+wire.Tag], n, rec, uint64(rel))
		return err
	})
}

// streamIn: поток → TUN.
func (c *Client) streamIn(ctx context.Context, id int, st *wire.Stream, rx *noise.Keys,
	dev tun.Device) error {
	s := &sess{} // нужен onFrame: в потоке из него используется только запись в устройство
	for ctx.Err() == nil {
		body, hdr, rel, err := st.ReadRecord()
		if err != nil {
			return err
		}
		pt, err := rx.Open(body, hdr, uint64(rel))
		if err != nil {
			// В потоке испорченная запись означает, что дальше читать нечего: границы следующей
			// известны только из длины, которой мы уже не верим.
			return fmt.Errorf("запись не расшифровалась: %w", err)
		}
		if len(pt) > 0 && pt[0] == wire.CtlBatch {
			if !wire.BatchIter(pt, func(f []byte) { c.onFrame(s, id, f, dev) }) {
				c.stats.dropped.Add(1)
			}
			continue
		}
		c.onFrame(s, id, pt, dev)
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
