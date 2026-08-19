package client

import (
	"context"
	"fmt"
	"time"

	"github.com/xyzmean/xsteer/link"
	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/wire"
)

// Одно рукопожатие на два транспорта.
//
// Пир ведёт записи либо по ПОДДЕЛЬНОМУ TCP (сырой сокет, датаграммная семантика), либо по
// НАСТОЯЩЕМУ потоку TCP (Windows и Android, где сырой сокет недоступен). Хореография Noise IK у
// них одна: собрать ClientHello, отправить, дождаться ПОЛНОГО ответа, разобрать его один раз,
// отправить подтверждение. Различается только рамка — как режется Hello, как приходит ответ, — и
// ровно она вынесена в интерфейс helloTransport. Так одно и то же рукопожатие обслуживает и первый
// подъём, и каждый повторный (переподключение идёт тем же путём), и его не приходится держать в
// двух согласованных копиях.

// handshaken — типизированный итог рукопожатия. Раньше эти же значения расходились по локальным
// переменным и полям sess в двух местах; здесь у них одно имя и один источник.
type handshaken struct {
	tx, rx *noise.Keys
	peer   noise.Payload
}

// helloTransport — рамка рукопожатия поверх конкретного транспорта.
type helloTransport interface {
	// sendHello отправляет ClientHello (транспорт сам решает, резать ли на сегменты).
	sendHello(hello []byte) error
	// readMore дочитывает ещё сколько-то байт ответа и возвращает накопленное. Если данных пока
	// нет, возвращает acc без изменений и nil — звать снова; истёкшее время или обрыв возвращаются
	// ошибкой.
	readMore(acc []byte) ([]byte, error)
	// sendConfirm отправляет подтверждение клиента.
	sendConfirm(b []byte) error
}

// doClientHandshake проводит рукопожатие до транспортных ключей. ClientFinish зовётся РОВНО ОДИН
// раз и только на целом ответе: он вбирает разбор в транскрипт, и на неполном ответе испортил бы
// его (см. noise.ResponseComplete).
func (c *Client) doClientHandshake(hs *noise.HS, t helloTransport, mtuSay, connID int,
	pq bool) (*handshaken, error) {

	hello, err := hs.ClientHello(c.opt.Sec.Priv, c.hub.pub, c.opt.Conf.SNI, mtuSay, connID,
		c.opt.AESPreferred, pq, nil)
	if err != nil {
		return nil, fmt.Errorf("рукопожатие не собралось: %w", err)
	}
	if err := t.sendHello(hello); err != nil {
		return nil, err
	}

	var acc []byte
	for !noise.ResponseComplete(acc) {
		acc, err = t.readMore(acc)
		if err != nil {
			return nil, err
		}
		// Ответ хаба заведомо меньше двух строк: ServerHello, фальшивый ChangeCipherSpec, запись
		// «сертификата» правдоподобной длины и подтверждение. Больше этого — не наш собеседник или
		// порча; копить дальше значило бы позволить чужому раздуть память.
		if len(acc) > 2*wire.Row {
			return nil, fmt.Errorf("хаб %s ответил не тем: %d байт без узнаваемого конца рукопожатия",
				c.hub.str, len(acc))
		}
	}

	tx, rx, _, err := hs.ClientFinish(acc)
	if err != nil {
		return nil, fmt.Errorf("хаб не признал нас или ответил не тем: %w", err)
	}
	confirm, err := hs.ClientConfirm(tx)
	if err != nil {
		return nil, err
	}
	if err := t.sendConfirm(confirm); err != nil {
		return nil, err
	}
	return &handshaken{tx: tx, rx: rx, peer: hs.Peer}, nil
}

// ---- поддельный TCP --------------------------------------------------------

// fakeHello — рамка рукопожатия поверх поддельного TCP-соединения.
type fakeHello struct {
	conn     *link.Conn
	buf      []byte
	ctx      context.Context
	deadline time.Time
	maxSeg   int
}

// sendHello режет Hello на сегменты, как это делает браузер: Hello больше одного сегмента по
// построению (постквантовый ключ), и одним куском он либо не дойдёт, либо приедет
// фрагментированным — и то и другое видно на проводе сразу.
func (t *fakeHello) sendHello(hello []byte) error {
	for off := 0; off < len(hello); off += t.maxSeg {
		end := off + t.maxSeg
		if end > len(hello) {
			end = len(hello)
		}
		if err := t.conn.Send(link.PSH|link.ACK, hello[off:end]); err != nil {
			return err
		}
	}
	return nil
}

func (t *fakeHello) readMore(acc []byte) ([]byte, error) {
	if time.Now().After(t.deadline) || t.ctx.Err() != nil {
		return acc, fmt.Errorf("хаб не ответил на рукопожатие")
	}
	ok, err := t.conn.WaitRead(200 * time.Millisecond)
	if err != nil {
		return acc, err
	}
	if !ok {
		return acc, nil
	}
	seg, mine, err := t.conn.Recv(t.buf)
	if err != nil {
		return acc, err
	}
	if !mine {
		return acc, nil
	}
	data, err := t.conn.OnSeg(&seg)
	if err != nil {
		return acc, err
	}
	if !data {
		return acc, nil
	}
	return append(acc, seg.Payload...), nil
}

func (t *fakeHello) sendConfirm(b []byte) error { return t.conn.Send(link.PSH|link.ACK, b) }

// ---- настоящий поток TCP ---------------------------------------------------

// streamHello — рамка рукопожатия поверх настоящего потока. Все чтения и записи идут через wire.Stream,
// чтобы смещение сторон двигалось на длину рукопожатия одинаково: иначе первый же пакет данных не
// расшифровался бы.
type streamHello struct {
	st *wire.Stream
}

// sendHello отправляет Hello одним вызовом: резать на сегменты — дело ядра, и оно делает это так же,
// как у браузера, у которого Hello тоже не влезает в один сегмент.
func (t *streamHello) sendHello(hello []byte) error { return t.st.WriteRaw(hello) }

func (t *streamHello) readMore(acc []byte) ([]byte, error) {
	var hdr [wire.RecHdr]byte
	if err := t.st.ReadFull(hdr[:]); err != nil {
		return acc, fmt.Errorf("хаб не ответил на рукопожатие: %w", err)
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n < 1 || n > wire.MaxRecord {
		return acc, fmt.Errorf("хаб ответил не тем: запись длиной %d", n)
	}
	body := make([]byte, n)
	if err := t.st.ReadFull(body); err != nil {
		return acc, err
	}
	acc = append(acc, hdr[:]...)
	return append(acc, body...), nil
}

func (t *streamHello) sendConfirm(b []byte) error { return t.st.WriteRaw(b) }
