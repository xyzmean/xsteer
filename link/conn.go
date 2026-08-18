package link

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/xyzmean/xsteer/wire"
)

// Пороги. Значения взяты из движка на C, кроме особо отмеченных.
const (
	TickMS     = 20
	SynRetryMS = 1000
	SynRetries = 6
	// AckSegs — через сколько принятых сегментов подтверждать. Двойка, а не восьмёрка, — из
	// ПРАВДОПОДОБИЯ: Linux подтверждает примерно через сегмент, и поток, подтверждающий раз в
	// восемь, отличим от настоящего именно ритмом. Цена на обратном пути загрузки — 40 байт на
	// два сегмента по 1500, то есть 1,3%; при двустороннем трафике голых подтверждений не нужно
	// вовсе.
	AckSegs = 2
	AckMS   = 40
	// DeadMS — тишина при АКТИВНОЙ отправке, после которой путь считается мёртвым.
	//
	// Сорок пять секунд, а не пятнадцать, и это не осторожность. Пятнадцать — порог WireGuard, и
	// на живом роутере он сработал ЛОЖНО: два посторонних процесса заняли оба ядра, наш получил
	// 4% времени, входящие сегменты пролежали в очереди дольше порога — и туннель пересоздался на
	// ровном месте. У WireGuard такой порог безопасен потому, что он НЕ РАЗРУШАЮЩИЙ: там
	// начинается новое рукопожатие, а прежняя сессия продолжает нести трафик. У нас
	// переподключение рвёт поддельное соединение, то есть стоит нового рукопожатия и проверки
	// пути. Сорок пять — это четыре пропущенных keepalive хаба; veil держит для того же 90 с с
	// той же мотивировкой.
	DeadMS = 45000
)

// Состояния поддельного соединения.
const (
	StateClosed = iota
	StateSynSent
	StateEst
)

// ErrDead — путь молчит при активной отправке. Отдельная ошибка: вызывающий на неё поднимает
// соединение заново, а не завершает работу.
var ErrDead = errors.New("link: путь молчит при активной отправке")

// Conn — поддельное TCP-соединение к хабу.
//
// ЗАМОК ЗДЕСЬ ЕСТЬ, В ОТЛИЧИЕ ОТ РЕАЛИЗАЦИИ НА C, и это следствие того, что цикл в Go устроен
// иначе. В C один поток на соединение и один poll на два дескриптора, поэтому состояние никому не
// приходится защищать. Здесь направления разведены по горутинам (блокирующее чтение вместо poll —
// так этот же код работает и на тех системах, где poll по TUN устроен по-другому), а значит номер
// последовательности трогают двое: поток данных и тот, кто отправляет подтверждения и keepalive.
//
// Цена замка названа честно: около двадцати наносекунд на пакет без соперничества против примерно
// микросекунды, которую на том же пакете стоит AEAD, — то есть проценты процента. Соперничество
// низкое по построению: обратный путь отправляет только голые подтверждения.
type Conn struct {
	mu sync.Mutex

	SAddr, DAddr [4]byte
	SPort, DPort uint16

	isnTX, isnRX uint32
	seq, ack     uint32
	state        int
	synTries     int
	unacked      int

	born, lastRX, lastTX, lastAck int64

	raw Raw
}

// Raw — сырой сокет. Интерфейс, а не структура, ровно по двум причинам: платформы устроены
// по-разному (на Windows сырой TCP запрещён вовсе, и там придётся ходить через перехватчик), а
// тест хочет соединение без прав root.
type Raw interface {
	Send(seg []byte) error
	Recv(buf []byte) (int, error)
	// WaitRead ждёт готовности к чтению не дольше timeout; false — истекло время.
	WaitRead(timeout time.Duration) (bool, error)
	Local() [4]byte
	Close() error
}

// Open открывает соединение и отправляет SYN.
//
// shard задаёт МЛАДШИЕ БИТЫ порта источника: порт выбираем мы сами, а хаб раскладывает соединения
// по своим воркерам именно по этим битам. Клиент с несколькими соединениями обязан дать им РАЗНЫЕ
// значения — иначе все его соединения достанутся одному воркеру хаба, и второе ядро там не
// заработает. Отрицательное значение означает «любой порт».
func Open(raw Raw, daddr [4]byte, dport int, shard int, isnTX uint32, sport uint16) (*Conn, error) {
	c := &Conn{
		raw:   raw,
		DAddr: daddr,
		DPort: uint16(dport),
		SPort: sport,
		isnTX: isnTX,
		SAddr: raw.Local(),
		state: StateSynSent,
	}
	if shard >= 0 {
		c.SPort = c.SPort&^uint16(wire.ConnsMax-1) | uint16(shard&(wire.ConnsMax-1))
	}
	c.seq = isnTX
	now := nowMS()
	c.born, c.lastRX, c.lastTX = now, now, now
	if err := c.send(SYN, nil, OptScale); err != nil {
		raw.Close()
		return nil, fmt.Errorf("link: SYN не ушёл: %w", err)
	}
	c.synTries = 1
	return c, nil
}

func nowMS() int64 {
	// Монотонные часы: время стенное на десктопе прыгает при синхронизации и при выходе из сна, и
	// «тишина сорок пять секунд» случилась бы на ровном месте — как раз после пробуждения ноутбука.
	return time.Now().UnixNano() / int64(time.Millisecond)
}

func (c *Conn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state = StateClosed
	return c.raw.Close()
}

// State — текущее состояние. Только для журнала и решений вызывающего.
func (c *Conn) State() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Age — сколько живёт соединение. Нужно пределам: ретайр наступает по объёму ИЛИ по времени.
func (c *Conn) Age() int64 { return nowMS() - c.born }

// send отправляет служебный сегмент или короткую нагрузку. Замок обязан быть взят вызывающим.
func (c *Conn) send(flags byte, payload []byte, opts int) error {
	buf := make([]byte, 60+len(payload))
	n := BuildSeg(buf, c.SAddr, c.DAddr, c.SPort, c.DPort, c.seq, c.ack, flags, opts, payload)
	err := c.raw.Send(buf[:n])
	// Номер двигается ДАЖЕ при неудачной отправке — см. инвариант в шапке пакета. Датаграмма
	// потеряна, номер потрачен; вернуть его назад значило бы однажды повторить nonce.
	c.seq += uint32(len(payload))
	if flags&SYN != 0 {
		c.seq++ // SYN занимает один номер
	}
	c.lastTX = nowMS()
	if flags&ACK != 0 {
		c.unacked = 0
		c.lastAck = c.lastTX
	}
	return err
}

// Send отправляет служебный сегмент под замком: для рукопожатия и keepalive.
func (c *Conn) Send(flags byte, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.send(flags, payload, OptNone)
}

// RelNext — смещение, с которым уйдёт СЛЕДУЮЩИЙ пакет данных: им шифруется его же нагрузка.
func (c *Conn) RelNext() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seq - c.isnTX
}

// RelOf — смещение принятого сегмента.
func (c *Conn) RelOf(seq uint32) uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return wire.Rel(seq, c.isnRX)
}

// SendData отправляет ОДИН пакет данных, заголовок которого пишется ПЕРЕД нагрузкой в том же
// буфере.
//
// row — строка длиной не меньше wire.HdrRoom + plen, где нагрузка (готовая запись: заголовок
// записи, шифротекст и тег) уже лежит по смещению wire.HdrRoom - wire.RecHdr. Копий нет: сегмент
// уходит с того места, где его собрали.
//
// Возвращает смещение, с которым пакет ушёл: вызывающий обязан был зашифровать нагрузку ИМЕННО им,
// поэтому получает его же обратно для проверки в отладке, а не для повторного использования.
func (c *Conn) SendData(row []byte, plen int) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateEst {
		return 0, errors.New("link: соединение не установлено")
	}
	off := wire.HdrRoom - wire.RecHdr - 20
	seg := row[off : wire.HdrRoom-wire.RecHdr+plen]
	for i := 0; i < 20; i++ {
		seg[i] = 0
	}
	putU16(seg[0:2], c.SPort)
	putU16(seg[2:4], c.DPort)
	putU32(seg[4:8], c.seq)
	putU32(seg[8:12], c.ack)
	seg[12] = 5 << 4
	seg[13] = PSH | ACK
	putU16(seg[14:16], Win)
	putU16(seg[16:18], Csum(c.SAddr, c.DAddr, seg))
	rel := c.seq - c.isnTX
	c.seq += uint32(plen)
	now := nowMS()
	c.lastTX, c.lastAck = now, now
	c.unacked = 0
	return rel, c.raw.Send(seg)
}

// OnSeg учитывает принятый сегмент: подтверждения, состояние, счётчики.
//
// data == true означает «несёт данные, которые надо разобрать»; err == ErrDead — пришёл RST, и
// соединение закрылось.
func (c *Conn) OnSeg(s *Seg) (data bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastRX = nowMS()
	if s.Flags&RST != 0 {
		c.state = StateClosed
		return false, ErrDead
	}
	if c.state == StateSynSent {
		if s.Flags&(SYN|ACK) != SYN|ACK {
			return false, nil
		}
		c.isnRX = s.Seq
		c.ack = s.Seq + 1
		c.state = StateEst
		// Подтверждаем рукопожатие сразу: без этого хаб не считает соединение установившимся и
		// будет повторять SYN-ACK.
		_ = c.send(ACK, nil, OptNone)
		return false, nil
	}
	if len(s.Payload) == 0 || c.state != StateEst {
		return false, nil
	}
	c.ack = NextAck(c.ack, s.Seq, len(s.Payload))
	c.unacked++
	return true, nil
}

// Tick: раз в TickMS — повторить SYN, отправить отложенное подтверждение, сказать про мёртвый путь.
//
// sending означает «мы отправили ПОСЛЕ того, как получили», а не «мы вообще когда-нибудь
// отправляли». Разница принципиальна: со вторым условием туннель на покое, однажды отправивший
// пакет, считался бы мёртвым навсегда.
func (c *Conn) Tick() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := nowMS()
	if c.state == StateSynSent {
		if now-c.lastTX >= SynRetryMS {
			if c.synTries >= SynRetries {
				return ErrDead
			}
			// Повтор ТОГО ЖЕ SYN: номер уже потрачен на первую попытку, поэтому откатываем его на
			// единицу перед отправкой — это единственное место, где номер идёт назад, и оно
			// безопасно, потому что нагрузки в SYN нет и nonce из него не выводится.
			c.seq--
			_ = c.send(SYN, nil, OptScale)
			c.synTries++
		}
		return nil
	}
	if c.state != StateEst {
		return nil
	}
	if c.unacked > 0 && (c.unacked >= AckSegs || now-c.lastAck >= AckMS) {
		_ = c.send(ACK, nil, OptNone)
	}
	// Мёртвый путь считается ТОЛЬКО при активной отправке: молчание на покое — это покой, а не
	// поломка, и поднимать из-за него соединение заново значило бы дёргать туннель на простое.
	if c.lastTX > c.lastRX && now-c.lastRX > DeadMS {
		return ErrDead
	}
	return nil
}

// SinceTX — сколько прошло с последней отправки. Нужно keepalive.
func (c *Conn) SinceTX() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return nowMS() - c.lastTX
}

// Recv читает один пакет с сырого сокета и разбирает его, отбрасывая всё, что не принадлежит
// этой четвёрке. Фильтр на сокете отбивает основную массу чужого ещё в ядре, но проверка нужна и
// здесь: фильтр отбирает по порту, а не по нашему соединению целиком.
func (c *Conn) Recv(buf []byte) (Seg, bool, error) {
	n, err := c.raw.Recv(buf)
	if err != nil {
		return Seg{}, false, err
	}
	s, ok := ParseSeg(buf[:n])
	if !ok || s.SPort != c.DPort || s.DPort != c.SPort {
		return Seg{}, false, nil
	}
	return s, true, nil
}

// WaitRead — ожидание на сыром сокете.
func (c *Conn) WaitRead(d time.Duration) (bool, error) { return c.raw.WaitRead(d) }

func putU16(b []byte, v uint16) { b[0], b[1] = byte(v>>8), byte(v) }
func putU32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}
