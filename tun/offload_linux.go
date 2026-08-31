//go:build linux

package tun

// РАЗГРУЗКА СЕГМЕНТАЦИИ НА УСТРОЙСТВЕ — самый большой выигрыш скорости, какой в этом коде есть, и
// он не в криптографии.
//
// ЧТО ИЗМЕРЕНО. Запись одного пакета 1400 байт в TUN стоит 3920 нс — это путь приёма ядра целиком:
// выделение skb, копия из пользовательской памяти, netfilter, маршрутизация. Запись СУПЕР-КАДРА из
// сорока пяти таких пакетов (один заголовок, 63 КБ нагрузки, размер сегмента в метаданных) стоит
// 12115 нс, то есть 269 нс на пакет — В 14,6 РАЗА дешевле. Ядро при этом либо отдаёт кадр целиком
// локальному сокету, либо режет его на выходе, а на роутере резать умеет сама микросхема
// (аппаратный TSO у mtk_eth_soc и почти любого современного контроллера). Ровно об этой разгрузке
// и речь, когда просят «hardware offloading»: пакет не собирается по одному ни у нас, ни в ядре.
//
// ЧТО ЭТО ЗА МЕХАНИЗМ. Флаг IFF_VNET_HDR добавляет перед каждым кадром десять байт метаданных
// virtio_net_hdr: тип разгрузки, размер сегмента, где начинается и куда писать контрольную сумму.
// TUNSETOFFLOAD говорит ядру, что мы умеем такие кадры ПРИНИМАТЬ, — и тогда ядро отдаёт нам
// склеенное (GRO) одним чтением вместо сорока пяти. Это тот же интерфейс, которым живут все
// виртуальные машины, то есть самый оттоптанный путь в ядре, а не экзотика.
//
// ГРАНИЦА ПРОВЕДЕНА ЗДЕСЬ И НИГДЕ БОЛЬШЕ. Путь данных (client, hub) по-прежнему читает и пишет ПО
// ОДНОМУ пакету и ничего не знает ни про супер-кадры, ни про virtio: приём разбирает склеенное на
// пакеты сам, отправка накапливает пробег и отдаёт его ядру одним куском. Единственное, что
// добавилось наружу, — Flush: «на этом всплеск кончился, отдавай накопленное». Без него пакет
// пролежал бы в буфере до следующего, то есть разгрузка стоила бы задержки, а её здесь просят
// убрать, а не добавить.
//
// ЧЕГО ЗДЕСЬ НЕТ НАМЕРЕННО. Склейки ПОТОКОВ (у ядра это таблица потоков в GRO): пробег ведётся один
// и только по подряд идущим пакетам одного потока. Причина в том, откуда пакеты приходят: из
// туннеля они выходят в том порядке, в каком их отправил пир, и поток загрузки — это длинная
// череда подряд идущих сегментов одного соединения. Таблица потоков дала бы выигрыш только на
// перемешанном трафике, а стоила бы поиска и вытеснения на каждом пакете.

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/xyzmean/xsteer/csum"
)

// ПОЛЯ ЗАГОЛОВКА VIRTIO ЧИТАЮТСЯ И ПИШУТСЯ В ПОРЯДКЕ ХОСТА, А НЕ В СЕТЕВОМ.
//
// Это не небрежность и не выбор: устройство tun согласовывает порядок только через
// VIRTIO_F_VERSION_1, которого оно не объявляет, поэтому ядро читает поля как __virtio16 в
// прежнем режиме — то есть родным порядком машины. Зашитый little-endian верен на amd64, arm64 и
// mipsle и НЕВЕРЕН на big-endian (mips, ppc): разгрузка сломалась бы там молча, «на одной
// архитектуре пакеты не доходят». Та же оговорка стоит у реализации на C (src/ext/tun.c).
var hostU16 = func() (get func([]byte) uint16, put func([]byte, uint16)) {
	var probe uint16 = 1
	if *(*byte)(unsafe.Pointer(&probe)) == 1 {
		return binary.LittleEndian.Uint16, binary.LittleEndian.PutUint16
	}
	return binary.BigEndian.Uint16, binary.BigEndian.PutUint16
}

var vnetGet, vnetPut = hostU16()

const (
	// vnetHdrLen — sizeof(struct virtio_net_hdr): флаги, тип разгрузки, длина заголовков, размер
	// сегмента, начало суммы, смещение суммы.
	vnetHdrLen = 10
	// frameMax — предел кадра. Столько же, сколько предел skb->len у ядра: длина в заголовке IP
	// шестнадцатибитная, и кадра длиннее не бывает.
	frameMax = 65535

	vnetNeedsCsum = 0x01
	vnetGSONone   = 0
	vnetGSOTCPv4  = 1
	vnetGSOTCPv6  = 4
	vnetGSOECN    = 0x80

	// segsMax — сколько пакетов кладём в один супер-кадр. Шестьдесят четыре: дальше выигрыш на
	// пакет уже плоский (63 КБ и так набираются сорока пятью полноразмерными), а вот цена одной
	// потери растёт — при локальной доставке кадр гибнет целиком.
	segsMax = 64
)

// offload — состояние разгрузки одного дескриптора очереди. Принадлежит ровно одной горутине на
// каждое направление: приём читает и разбирает, отправка накапливает и отдаёт. Оба буфера свои,
// поэтому замка нет.
type offload struct {
	// rf и wf — чтение и запись дескриптора. Функциями, а не дескриптором, ровно ради теста:
	// разбор супер-кадра и склейка пробега — это арифметика, которую надо проверять векторами, а не
	// живым устройством, для которого нужны права root.
	rf func([]byte) (int, error)
	wf func([]byte) (int, error)

	// ---- приём ----
	rd []byte // vnetHdrLen + frameMax: кадр, как его отдало ядро
	// Разбор последнего супер-кадра. hdr — заголовки (IP и TCP), body — нагрузка целиком.
	hdr     []byte
	body    []byte
	gso     int // размер сегмента
	segN    int // сколько сегментов в кадре
	segI    int // сколько уже отдано
	v6      bool
	single  []byte // одиночный пакет: отдаём как есть, без пересчёта
	baseSeq uint32
	baseID  uint16
	flags   byte

	// ---- отправка ----
	wr     []byte // vnetHdrLen + frameMax
	wrLen  int    // длина накопленного пакета от заголовка IP
	wrSegs int
	wrGSO  int // размер сегмента пробега
	wrHdr  int // длина заголовков (IP и TCP)
	wrIPH  int // длина заголовка IP
	wrV6   bool
	wrSeq  uint32 // какой номер последовательности обязан быть у продолжения
	wrShut bool   // пробег закрыт: пришёл короткий сегмент или FIN

	// Dropped — кадры, которые не удалось ни разобрать, ни отдать. Не отказ, но и не ноль на
	// исправной системе: растёт, значит ядро отдаёт то, чего мы не умеем.
	Dropped uint64
}

// tryOffload включает разгрузку на уже открытом дескрипторе. Ошибка НЕ отказ подъёма: старое ядро
// (или сборка без TUN_F_TSO) означает лишь прежний путь по одному пакету, и это рабочий путь.
//
// Порядок обязателен: сначала размер заголовка метаданных, потом набор разгрузок. Наоборот ядро
// принимает TUNSETOFFLOAD, но кадры отдаёт с заголовком, которого мы не ждём.
func tryOffload(fd int) (*offload, error) {
	sz := vnetHdrLen
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETVNETHDRSZ),
		uintptr(unsafe.Pointer(&sz))); e != 0 {
		return nil, fmt.Errorf("TUNSETVNETHDRSZ: %v", e)
	}
	// TUN_F_CSUM обязателен: без него ядро не отдаёт ни склеенного, ни с неполной суммой, а
	// TUN_F_TSO* без него не принимается вовсе.
	feat := uintptr(unix.TUN_F_CSUM | unix.TUN_F_TSO4 | unix.TUN_F_TSO6)
	if _, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETOFFLOAD), feat); e != 0 {
		return nil, fmt.Errorf("TUNSETOFFLOAD: %v", e)
	}
	return newOffload(
		func(p []byte) (int, error) { return readFD(fd, p) },
		func(p []byte) (int, error) { return writeFD(fd, p) },
	), nil
}

func newOffload(rf, wf func([]byte) (int, error)) *offload {
	return &offload{
		rf: rf,
		wf: wf,
		rd: make([]byte, vnetHdrLen+frameMax),
		wr: make([]byte, vnetHdrLen+frameMax),
	}
}

// ---- приём -------------------------------------------------------------------

// read отдаёт ОДИН пакет. Пока в разобранном супер-кадре остались сегменты, системного вызова не
// происходит вовсе — ровно в этом и выигрыш на приёме.
func (o *offload) read(p []byte) (int, error) {
	for {
		if o.single != nil {
			n := len(o.single)
			if n > len(p) {
				o.single = nil
				o.Dropped++
				continue
			}
			copy(p, o.single)
			o.single = nil
			return n, nil
		}
		if o.segI < o.segN {
			n, err := o.emit(p)
			if err != nil {
				o.Dropped++
				continue
			}
			return n, nil
		}
		n, err := o.rf(o.rd)
		if err != nil {
			return 0, err
		}
		if n <= vnetHdrLen {
			continue
		}
		o.take(o.rd[:n])
	}
}

// take разбирает кадр, только что прочитанный из устройства: либо это одиночный пакет (может быть с
// НЕПОЛНОЙ суммой, которую ядро оставило устройству, — её мы обязаны достроить), либо склеенный
// супер-кадр, который надо разложить на сегменты.
func (o *offload) take(frame []byte) {
	flags := frame[0]
	gsoType := frame[1] &^ vnetGSOECN
	hdrLen := int(vnetGet(frame[2:4]))
	gsoSize := int(vnetGet(frame[4:6]))
	csumStart := int(vnetGet(frame[6:8]))
	csumOff := int(vnetGet(frame[8:10]))
	pkt := frame[vnetHdrLen:]

	o.segI, o.segN, o.single = 0, 0, nil

	if gsoType == vnetGSONone {
		// Неполная сумма: в поле лежит сумма псевдозаголовка, тело не просуммировано. Так ядро
		// отдаёт пакеты СВОИХ сокетов — оно оставляет сумму устройству. Отправить такой пакет в
		// туннель как есть значит отдать пиру пакет, который его же стек молча выбросит.
		if flags&vnetNeedsCsum != 0 {
			if csumStart+csumOff+2 > len(pkt) {
				o.Dropped++
				return
			}
			// Поле с неполной суммой входит в считаемый отрезок, поэтому отдельного слагаемого не
			// нужно: то же самое делает ядро в skb_checksum_help.
			binary.BigEndian.PutUint16(pkt[csumStart+csumOff:], csum.Of(pkt[csumStart:]))
		}
		o.single = pkt
		return
	}

	// Склеенное. Заголовки общие, нагрузка нарезается по gsoSize.
	if gsoSize <= 0 || hdrLen < 40 || hdrLen > len(pkt) {
		o.Dropped++
		return
	}
	switch gsoType {
	case vnetGSOTCPv4:
		if pkt[0]>>4 != 4 || int(pkt[0]&0x0F)*4+20 > hdrLen {
			o.Dropped++
			return
		}
		o.v6 = false
	case vnetGSOTCPv6:
		if pkt[0]>>4 != 6 {
			o.Dropped++
			return
		}
		o.v6 = true
	default:
		// UDP-разгрузку мы у ядра не просили; если она всё же пришла — в счётчик, а не наугад.
		o.Dropped++
		return
	}
	iph := 20
	if o.v6 {
		iph = 40
	}
	th := pkt[iph:hdrLen]
	if len(th) < 20 {
		o.Dropped++
		return
	}
	o.hdr = pkt[:hdrLen]
	o.body = pkt[hdrLen:]
	o.gso = gsoSize
	o.segN = (len(o.body) + gsoSize - 1) / gsoSize
	o.baseSeq = binary.BigEndian.Uint32(th[4:8])
	o.flags = th[13]
	if !o.v6 {
		o.baseID = binary.BigEndian.Uint16(pkt[4:6])
	}
	if o.segN == 0 {
		o.Dropped++
	}
}

// emit собирает сегмент i супер-кадра в p: общие заголовки, своя нагрузка, свои номер
// последовательности, длина, идентификатор IP и обе контрольные суммы.
//
// Фиксовки повторяют то, что делает ядро в tcp_gso_segment и inet_gso_segment, и повторяют по
// причине: сегменты обязаны быть неотличимы от тех, которые пришли бы без склейки, — иначе стек
// пира увидит поток, которого не бывает.
func (o *offload) emit(p []byte) (int, error) {
	i := o.segI
	o.segI++
	off := i * o.gso
	end := off + o.gso
	if end > len(o.body) {
		end = len(o.body)
	}
	last := o.segI >= o.segN
	n := len(o.hdr) + (end - off)
	if n > len(p) {
		return 0, fmt.Errorf("tun: сегмент %d байт не влезает в буфер %d", n, len(p))
	}
	copy(p, o.hdr)
	copy(p[len(o.hdr):], o.body[off:end])
	seg := p[:n]

	iph := 20
	if o.v6 {
		iph = 40
	}
	// th — ВСЯ часть TCP, а не только заголовок: по её длине считается сумма. Срез по длине
	// заголовка давал сумму, посчитанную над двадцатью байтами вместо сегмента целиком, — то есть
	// пакет с неверной суммой, который стек пира выбрасывает молча.
	th := seg[iph:]
	// Номер последовательности сдвигается на СМЕЩЕНИЕ В НАГРУЗКЕ, а не на номер сегмента.
	binary.BigEndian.PutUint32(th[4:8], o.baseSeq+uint32(off))
	// FIN и PSH — только на последнем сегменте: ровно так режет ядро. Оставить их на каждом значило
	// бы закрыть соединение пира на первом же сегменте склеенной пачки.
	if last {
		th[13] = o.flags
	} else {
		th[13] = o.flags &^ (0x01 | 0x08)
	}
	if o.v6 {
		binary.BigEndian.PutUint16(seg[4:6], uint16(n-40))
	} else {
		binary.BigEndian.PutUint16(seg[2:4], uint16(n))
		// Идентификатор растёт на сегмент — так же, как в inet_gso_segment.
		binary.BigEndian.PutUint16(seg[4:6], o.baseID+uint16(i))
		seg[10], seg[11] = 0, 0
		binary.BigEndian.PutUint16(seg[10:12], csum.Of(seg[:20]))
	}
	// Сумма TCP считается полностью: в супер-кадре лежала неполная (сумма псевдозаголовка по ВСЕЙ
	// его длине), и для сегмента она не годится ни одним байтом.
	th[16], th[17] = 0, 0
	var ps uint64
	if o.v6 {
		ps = csum.PseudoV6(seg[8:24], seg[24:40], 6, len(th))
	} else {
		ps = csum.PseudoV4(seg[12:16], seg[16:20], 6, len(th))
	}
	binary.BigEndian.PutUint16(th[16:18], csum.Fold(ps+csum.Sum(th)))
	return n, nil
}

// ---- отправка ----------------------------------------------------------------

// tcpRun — что нужно знать о пакете, чтобы решить, продолжает ли он пробег.
type tcpRun struct {
	ok    bool
	v6    bool
	iph   int
	hdr   int // iph + длина заголовка TCP
	plen  int
	seq   uint32
	flags byte
}

// lookTCP смотрит пакет: годится ли он в супер-кадр вообще.
//
// Отказ здесь не редкость и не беда: пакет уедет в ядро один, как и раньше. Годятся только
// НЕФРАГМЕНТИРОВАННЫЕ сегменты TCP без опций IP — всё прочее ядро в склейке не приняло бы тоже.
func lookTCP(p []byte) (r tcpRun) {
	if len(p) < 40 {
		return
	}
	switch p[0] >> 4 {
	case 4:
		r.iph = int(p[0]&0x0F) * 4
		// Опции IP запрещены: заголовок супер-кадра копируется во все сегменты, и опция с
		// маршрутом записи повторилась бы в каждом. Ядро в GRO их тоже не склеивает.
		if r.iph != 20 || p[9] != 6 {
			return
		}
		// Фрагмент (смещение или флаг «ещё будет») — не сегмент.
		if binary.BigEndian.Uint16(p[6:8])&0x3FFF != 0 {
			return
		}
		total := int(binary.BigEndian.Uint16(p[2:4]))
		if total != len(p) {
			return
		}
	case 6:
		r.v6 = true
		r.iph = 40
		if p[6] != 6 {
			return
		}
		if 40+int(binary.BigEndian.Uint16(p[4:6])) != len(p) {
			return
		}
	default:
		return
	}
	if len(p) < r.iph+20 {
		return
	}
	th := p[r.iph:]
	thl := int(th[12]>>4) * 4
	if thl < 20 || r.iph+thl > len(p) {
		return
	}
	r.hdr = r.iph + thl
	r.plen = len(p) - r.hdr
	r.seq = binary.BigEndian.Uint32(th[4:8])
	r.flags = th[13]
	r.ok = true
	return
}

// write накапливает пакет в пробег или отдаёт накопленное и начинает новый.
func (o *offload) write(p []byte) (int, error) {
	r := lookTCP(p)
	// Пакет, которому в супер-кадре не место (UDP, ICMP, фрагмент, голое подтверждение), уезжает
	// один — но накопленное перед ним обязано уйти ПЕРВЫМ, иначе порядок пакетов в потоке
	// изменится. Порядок здесь не косметика: внутренний TCP считает переупорядочивание потерей.
	// SYN, RST и флаги перегрузки закрывают пробег по той же причине, по которой их не склеивает
	// ядро: у них своя семантика на каждом сегменте.
	const noRun = 0x02 | 0x04 | 0x20 | 0x40 | 0x80 // SYN, RST, URG, ECE, CWR
	if !r.ok || r.plen == 0 || r.flags&noRun != 0 {
		if err := o.Flush(); err != nil {
			return 0, err
		}
		return o.writeOne(p)
	}
	if o.wrSegs > 0 && o.canAppend(p, r) {
		o.appendRun(p, r)
		return len(p), nil
	}
	if err := o.Flush(); err != nil {
		return 0, err
	}
	o.startRun(p, r)
	return len(p), nil
}

// canAppend — продолжает ли пакет накопленный пробег.
//
// Условия те же, по которым склеивает ядро (tcp_gro_receive), и каждое из них обязательно:
// одинаковый поток и одинаковая длина заголовков (заголовок в супер-кадре ОДИН на всех), номер
// последовательности вплотную к накопленному (иначе в потоке появится дыра), и размер сегмента
// РОВНО такой же — кроме последнего, который может быть короче и после которого пробег закрыт.
func (o *offload) canAppend(p []byte, r tcpRun) bool {
	if o.wrShut || o.wrSegs >= segsMax || r.v6 != o.wrV6 || r.hdr != o.wrHdr {
		return false
	}
	if r.seq != o.wrSeq || r.plen > o.wrGSO {
		return false
	}
	if o.wrLen+r.plen > frameMax {
		return false
	}
	// Тот же поток: адреса и порты. Сравниваем прямо в накопленном кадре — копии заголовка для
	// этого не нужно.
	a := o.wr[vnetHdrLen:]
	if o.wrV6 {
		if string(a[8:40]) != string(p[8:40]) {
			return false
		}
	} else if string(a[12:20]) != string(p[12:20]) {
		return false
	}
	return string(a[o.wrIPH:o.wrIPH+4]) == string(p[o.wrIPH:o.wrIPH+4])
}

func (o *offload) startRun(p []byte, r tcpRun) {
	copy(o.wr[vnetHdrLen:], p)
	o.wrLen = len(p)
	o.wrSegs = 1
	o.wrGSO = r.plen
	o.wrHdr = r.hdr
	o.wrIPH = r.iph
	o.wrV6 = r.v6
	o.wrSeq = r.seq + uint32(r.plen)
	o.wrShut = false
}

// appendRun добавляет нагрузку к пробегу.
//
// Из заголовка нового пакета берутся поля, которые ядро в склейке берёт от ПОСЛЕДНЕГО сегмента:
// номер подтверждения, объявляемое окно и опции (в них живёт метка времени, и она меняется на
// каждом сегменте). Флаг PSH накапливается: он означает «конец записи приложения», и потерять его
// значит задержать данные у получателя.
func (o *offload) appendRun(p []byte, r tcpRun) {
	copy(o.wr[vnetHdrLen+o.wrLen:], p[r.hdr:])
	o.wrLen += r.plen
	o.wrSegs++
	o.wrSeq = r.seq + uint32(r.plen)
	a := o.wr[vnetHdrLen:]
	th := a[o.wrIPH:o.wrHdr]
	nth := p[r.iph:r.hdr]
	copy(th[8:12], nth[8:12])   // подтверждение
	copy(th[14:16], nth[14:16]) // окно
	if len(th) > 20 {
		copy(th[20:], nth[20:]) // опции: метка времени последнего сегмента
	}
	th[13] |= nth[13] & 0x08 // PSH накапливается
	if nth[13]&0x01 != 0 {
		th[13] |= 0x01 // FIN — только у последнего, и после него пробег закрыт
		o.wrShut = true
	}
	if r.plen < o.wrGSO {
		// Короткий сегмент допустим только последним: ядро при нарезке даёт короткий хвост, а
		// короткий в СЕРЕДИНЕ означал бы сегменты не того размера.
		o.wrShut = true
	}
}

// Flush отдаёт накопленный пробег ядру. Зовётся путём данных на границе всплеска — то есть когда
// читать больше нечего, — и потому не добавляет ни микросекунды задержки.
func (o *offload) Flush() error {
	if o.wrSegs == 0 {
		return nil
	}
	segs := o.wrSegs
	n := o.wrLen
	o.wrSegs, o.wrLen = 0, 0
	pkt := o.wr[vnetHdrLen : vnetHdrLen+n]
	hdr := o.wr[:vnetHdrLen]
	for i := range hdr {
		hdr[i] = 0
	}
	if segs > 1 {
		// Длина в заголовке IP обязана быть длиной ВСЕГО кадра: по ней ip_rcv подрезает пакет, и
		// прежнее значение (один сегмент) означало бы, что вся склейка кроме первого сегмента
		// отброшена молча.
		if o.wrV6 {
			binary.BigEndian.PutUint16(pkt[4:6], uint16(n-40))
		} else {
			binary.BigEndian.PutUint16(pkt[2:4], uint16(n))
			pkt[10], pkt[11] = 0, 0
			binary.BigEndian.PutUint16(pkt[10:12], csum.Of(pkt[:20]))
		}
		// Сумма TCP оставляется УСТРОЙСТВУ: в поле кладётся свёрнутая сумма псевдозаголовка по
		// полной длине кадра — именно её ядро правит на длину каждого сегмента при нарезке
		// (tcp_gso_segment), а достраивает нагрузкой уже микросхема. Полная сумма здесь была бы и
		// лишней работой, и неверным числом.
		th := pkt[o.wrIPH:]
		var ps uint64
		if o.wrV6 {
			ps = csum.PseudoV6(pkt[8:24], pkt[24:40], 6, len(th))
		} else {
			ps = csum.PseudoV4(pkt[12:16], pkt[16:20], 6, len(th))
		}
		binary.BigEndian.PutUint16(th[16:18], csum.FoldNoInv(ps))
		hdr[0] = vnetNeedsCsum
		if o.wrV6 {
			hdr[1] = vnetGSOTCPv6
		} else {
			hdr[1] = vnetGSOTCPv4
		}
		vnetPut(hdr[2:4], uint16(o.wrHdr))
		vnetPut(hdr[4:6], uint16(o.wrGSO))
		vnetPut(hdr[6:8], uint16(o.wrIPH))
		vnetPut(hdr[8:10], 16)
	}
	// Один сегмент — обычный кадр с нулевыми метаданными: сумма в нём уже верная (пакет приехал из
	// туннеля целиком), и просить ядро считать её заново незачем.
	_, err := o.wf(o.wr[:vnetHdrLen+n])
	return err
}

// writeOne отдаёт один пакет мимо накопления: метаданные нулевые.
func (o *offload) writeOne(p []byte) (int, error) {
	hdr := o.wr[:vnetHdrLen]
	for i := range hdr {
		hdr[i] = 0
	}
	n := copy(o.wr[vnetHdrLen:], p)
	if _, err := o.wf(o.wr[:vnetHdrLen+n]); err != nil {
		return 0, err
	}
	return n, nil
}
