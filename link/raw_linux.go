//go:build linux

package link

import (
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// rawLinux — сырой сокет IPPROTO_TCP.
//
// Заголовок IP заполняет ЯДРО (IP_HDRINCL не ставим): адреса, идентификатор и сумму оно посчитает
// правильнее, а на приёме всё равно отдаст пакет целиком с заголовка. Взамен мы обязаны считать
// сумму TCP сами — её сырой сокет не заполняет, и забыть это значит получить поток, который
// conntrack по дороге считает недействительным.
type rawLinux struct {
	fd    int
	local [4]byte
	// noBatch — ядро отказало в sendmmsg (его нет вовсе). Спрашивать второй раз незачем.
	noBatch bool
}

// OpenRaw открывает сырой сокет к daddr и ставит на него фильтр.
//
// ФИЛЬТР СТАВИТСЯ ДО ПЕРВОГО SYN, и это не мелочь: сырой сокет получает КОПИЮ каждого локально
// доставляемого сегмента TCP, и между socket() и настройкой фильтра очередь успевает набрать
// чужого — на нагруженной машине это тысячи пакетов, из-за которых теряются настоящие.
//
// СОКЕТ НЕБЛОКИРУЮЩИЙ, и это не мелочь настройки, а минус один системный вызов на каждый принятый
// пакет. С блокирующим сокетом узнать «пришло ли ещё» можно было только через poll, поэтому цикл
// приёма делал poll ПЕРЕД КАЖДЫМ чтением: на полутора гигабитах это пятьдесят тысяч лишних вызовов
// в секунду. С O_NONBLOCK цикл читает, пока не получит ErrAgain, и ждёт только тогда, когда очередь
// действительно пуста. Ровно так же устроены сокет хаба (OpenRawListen) и устройство TUN.
func OpenRaw(daddr [4]byte, sport, dport uint16) (Raw, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP)
	if err != nil {
		if err == unix.EPERM {
			return nil, fmt.Errorf("сырой сокет запрещён: нужен root или CAP_NET_RAW " +
				"(setcap cap_net_raw,cap_net_admin+ep на исполняемый файл)")
		}
		return nil, fmt.Errorf("сырой сокет: %w", err)
	}
	r := &rawLinux{fd: fd}
	// Не ставим DF: путь с меньшим MTU при ошибке в настройке даст фрагментацию, а не тихую
	// пропажу больших пакетов.
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)

	sa := &unix.SockaddrInet4{Addr: daddr}
	if err := unix.Connect(fd, sa); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("connect к %d.%d.%d.%d: %w", daddr[0], daddr[1], daddr[2], daddr[3], err)
	}
	// Адрес источника выбирает ядро — тот, с которого мы фактически уходим. Спрашивать таблицу
	// маршрутизации не нужно, и это же даёт имя интерфейса для предела MTU.
	local, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	if in4, ok := local.(*unix.SockaddrInet4); ok {
		r.local = in4.Addr
	}
	if err := filterQuad(fd, daddr, sport, dport); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return r, nil
}

func (r *rawLinux) Send(seg []byte) error {
	for {
		err := unix.Send(r.fd, seg, unix.MSG_NOSIGNAL)
		switch err {
		case nil:
			return nil
		case unix.EINTR:
			continue
		default:
			return sendErr(err)
		}
	}
}

// SendBatch отдаёт сегменты одним sendmmsg: по два куска на сегмент — свой заголовок и срез тела в
// записи.
//
// ЗАМЕР, из которого это выросло (эта машина, сегмент 1480 байт в сырой сокет): по одному 3325 нс,
// пачкой по восемь 2641 нс, пачкой по 64 — 2543 нс. Снимается около четверти, и снимается с самого
// дорогого шага на быстрой машине: путь вывода ядра стоит там больше, чем шифр и сумма вместе.
// Дорог при этом НЕ вход в ядро — иначе выигрыш был бы кратным, — а сам путь вывода, и это стоит
// знать, прежде чем искать здесь разы.
//
// НЕОТПРАВЛЕННЫЙ ОСТАТОК НЕ ПОВТОРЯЕТСЯ, и это не упрощение. Номера последовательности на всю запись
// уже потрачены (см. инвариант в шапке пакета), а повтор с теми же номерами означал бы второй пакет
// с тем же nonce. Потерянная датаграмма — обычное дело для этого протокола; повтор nonce —
// полная потеря стойкости AEAD.
func (r *rawLinux) SendBatch(segs []Seglet) (int, error) {
	if len(segs) == 0 {
		return 0, nil
	}
	if r.noBatch {
		return 0, errNoBatch
	}
	// Массивы на стеке: пачка не длиннее batchSegs по построению, и выделять под неё память на
	// каждую запись значило бы отдать сборщику мусора горячий путь.
	var (
		msgs [batchSegs]mmsghdr
		iovs [batchSegs][2]unix.Iovec
	)
	n := len(segs)
	if n > batchSegs {
		n = batchSegs
	}
	for i := 0; i < n; i++ {
		iovs[i][0].Base = &segs[i].Hdr[0]
		iovs[i][0].SetLen(len(segs[i].Hdr))
		iovs[i][1].Base = &segs[i].Body[0]
		iovs[i][1].SetLen(len(segs[i].Body))
		msgs[i].hdr.Iov = &iovs[i][0]
		msgs[i].hdr.SetIovlen(2)
	}
	for {
		got, _, e := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(r.fd),
			uintptr(unsafe.Pointer(&msgs[0])), uintptr(n), uintptr(unix.MSG_NOSIGNAL), 0, 0)
		if e == unix.EINTR {
			continue
		}
		if e != 0 {
			// ENOSYS означает ядро без sendmmsg (до 3.0) — тогда пачки нет вовсе и спрашивать о ней
			// больше не надо. Прочие ошибки разбирает вызывающий как обычные ошибки отправки.
			if e == unix.ENOSYS || e == unix.EOPNOTSUPP {
				r.noBatch = true
				return 0, errNoBatch
			}
			return 0, sendErr(e)
		}
		return int(got), nil
	}
}

// mmsghdr — struct mmsghdr ядра: заголовок сообщения и сколько байт ушло.
//
// ОПИСАН ЗДЕСЬ, ПОТОМУ ЧТО В x/sys ЕГО НЕТ. Раскладка выходит верной сама: unix.Msghdr описан там
// же и той же генерацией, а естественное выравнивание Go совпадает с сишным на обеих ширинах слова
// (на 64-битных 56+4 с добивкой до 64, на 32-битных 28+4 без добивки). Проверять это рассуждением
// всё равно нельзя, поэтому проверяет стенд: пачка отправляется в настоящий сокет, пакеты ловятся с
// провода и сверяются побайтово с тем, что даёт отправка по одному (см. TestПачкаНаПроводеТаЖе).
type mmsghdr struct {
	hdr unix.Msghdr
	len uint32
}

// sendErr распознаёт «пути наружу больше нет».
//
// Сокет ПОДКЛЮЧЁН, то есть адрес источника у него закреплён при открытии, и после смены адреса он не
// годится вовсе — его надо открывать заново, а не повторять отправку. EINVAL в списке именно поэтому:
// так ядро отвечает на отправку с адреса, которого на машине больше нет.
func sendErr(err error) error {
	switch err {
	case nil:
		return nil
	case unix.ENETUNREACH, unix.ENETDOWN, unix.EHOSTUNREACH, unix.EADDRNOTAVAIL, unix.EINVAL:
		return fmt.Errorf("%w: %v", ErrPathGone, err)
	}
	return err
}

func (r *rawLinux) Recv(buf []byte) (int, error) {
	for {
		n, err := unix.Read(r.fd, buf)
		switch err {
		case nil:
			return n, nil
		case unix.EINTR:
			continue
		case unix.EAGAIN:
			// НЕ отказ: очередь пуста. Отдельной ошибкой, потому что вызывающий на ней перестаёт
			// добирать пакеты и отдаёт накопленное, а на всякой прочей — поднимает соединение
			// заново. Спутать это значило бы рвать туннель на каждом пустом чтении.
			return 0, ErrAgain
		default:
			return n, err
		}
	}
}

// WaitRead ждёт готовности. Через poll, а не через runtime Go: дескриптор сырого сокета не
// зарегистрирован в сетевом опросчике Go, и обёртывать его в os.File ради этого значило бы
// получить второй способ читать тот же сокет.
func (r *rawLinux) WaitRead(d time.Duration) (bool, error) {
	fds := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}
	ms := int(d / time.Millisecond)
	if ms < 0 {
		ms = -1
	}
	for {
		n, err := unix.Poll(fds, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return false, err
		}
		return n > 0, nil
	}
}

func (r *rawLinux) Local() [4]byte { return r.local }
func (r *rawLinux) Close() error   { return unix.Close(r.fd) }

// filterQuad — фильтр cBPF: пропускать только сегменты этой четвёрки.
//
// Без фильтра очередь сокета переполняется чужим (сырой сокет получает копию каждого локально
// доставляемого TCP) и теряет настоящие сегменты — на первом замере в движке на C это стоило
// 146 тысяч потерь.
func filterQuad(fd int, server [4]byte, sport, dport uint16) error {
	srv := uint32(server[0])<<24 | uint32(server[1])<<16 | uint32(server[2])<<8 | uint32(server[3])
	// Инструкции ровно те же, что в obfs_filter_quad движка: адрес источника, затем порты через
	// косвенную загрузку по длине заголовка IP (X = ihl).
	prog := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 12},          // ip saddr
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: srv, Jf: 5}, //
		{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0},          // X = ihl
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 0},           // tcp sport
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(dport), Jf: 3},
		{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2}, // tcp dport
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(sport), Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0xFFFFFFFF},
		{Code: unix.BPF_RET | unix.BPF_K, K: 0},
	}
	p := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &p); err != nil {
		return fmt.Errorf("фильтр не встал: %w", err)
	}
	return nil
}

// EgressMTU — MTU интерфейса, через который мы уходим к той стороне, и его имя.
//
// Нужен потому, что предел MTU туннеля обязан считаться от НАСТОЯЩЕГО канала, а не от
// предположения «1500». Замер на живом роутере: канал PPPoE 1492, то есть предел 1431, а
// умолчание 1439 было бы уже велико — и большие пакеты пропадали бы молча.
//
// Ищем по адресу, который ядро выбрало источником: он принадлежит ровно тому интерфейсу, через
// который мы уходим.
func EgressMTU(local [4]byte) (mtu int, ifname string) {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0, ""
	}
	want := net.IPv4(local[0], local[1], local[2], local[3])
	for _, in := range ifs {
		addrs, err := in.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if ok && ipn.IP.To4() != nil && ipn.IP.To4().Equal(want.To4()) {
				return in.MTU, in.Name
			}
		}
	}
	return 0, ""
}

// OpenRawSend — сырой сокет ТОЛЬКО для отправки конкретному адресу.
//
// saddr — адрес источника, С КОТОРОГО обязаны уходить наши пакеты. Нулевой означает «выбери сам,
// ядро».
//
// ЗАЧЕМ ЕГО НАЗЫВАТЬ, А НЕ ОСТАВЛЯТЬ ЯДРУ. Хаб отвечает пиру тем адресом, НА КОТОРЫЙ пир написал, а
// не тем, который ядро выберет для обратного маршрута. У хаба с одним адресом это одно и то же, а у
// многоадресного — нет, и расхождение ломает туннель молча сразу по двум причинам: сумма TCP
// считается с адресом из принятого сегмента (link.Accept берёт SAddr именно оттуда), а фильтр на
// сокете клиента пропускает только сегменты С АДРЕСА ХАБА — ответ с другого адреса ядро клиента
// отбрасывает ещё до нашего кода.
//
// Найдено стендом переезда (tests/roam.sh): пир, пришедший к тому же хабу другим путём, получал в
// ответ тишину, потому что хаб отвечал ему с адреса того интерфейса, через который лежал обратный
// маршрут.
//
// Фильтр ставится глухой: принимать этому сокету нечего, а без фильтра он получал бы копию каждого
// локально доставляемого сегмента TCP и переполнял бы очередь — на хабе с тридцатью сессиями это
// тридцать лишних копий каждого пакета.
func OpenRawSend(daddr, saddr [4]byte) (Raw, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("сырой сокет: %w", err)
	}
	r := &rawLinux{fd: fd}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DONT)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<20)
	if saddr != [4]byte{} {
		// Отказ здесь НЕ отказ отправки: адрес мог уехать между приёмом сегмента и этой строкой, и
		// тогда лучше ответить с того, который выберет ядро, чем не ответить вовсе.
		_ = unix.Bind(fd, &unix.SockaddrInet4{Addr: saddr})
	}
	if err := unix.Connect(fd, &unix.SockaddrInet4{Addr: daddr}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("connect: %w", err)
	}
	if local, err := unix.Getsockname(fd); err == nil {
		if in4, ok := local.(*unix.SockaddrInet4); ok {
			r.local = in4.Addr
		}
	}
	if err := filterNone(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return r, nil
}

// OpenRawListen — сырой сокет хаба: принимает сегменты, адресованные порту.
//
// mask и id — РАСКЛАДКА ПО ВОРКЕРАМ по младшим битам порта источника. Раскладку делает ядро
// фильтром, а не мы очередью с замком, и это несущее решение: поддельное соединение принадлежит
// ровно одному воркеру навсегда, поэтому окно приёма, ключи расшифровки и счётчик nonce — его
// личная собственность.
//
// Раскладка ИМЕННО по порту источника, а не по адресу: за одним NAT может сидеть вся звезда, и по
// адресу все соединения достались бы одному воркеру. Маска обязана быть степенью двойки минус один:
// у cBPF нет деления.
// Сокет НЕБЛОКИРУЮЩИЙ, и это не мелочь настройки, а условие живости хаба.
//
// rxLoop вычерпывает до 64 сегментов на одно событие готовности и выходит из цикла по ошибке
// чтения. С блокирующим сокетом «ошибки» не бывает: как только придёт хотя бы один сегмент,
// воркер уходит в чтения и НЕ ВЫХОДИТ из них, пока не наберёт все 64. На разреженном трафике
// (сессии, которые присылают только keepalive раз в десять секунд) между вызовами maintain()
// проходило до шестидесяти трёх межпакетных интервалов, то есть минуты. А в maintain живёт всё,
// что делает туннель живым: keepalive хаба (без него односторонний трафик выглядит для пира
// обрывом), уборка простоявших и смещённых сессий, отложенное подтверждение, проверка мёртвого
// пути и возврат размера пачки после всплеска потерь.
//
// Туннель при этом выживал случайно: lastRX пира обновляли голые подтверждения, которые уходят
// из OnSeg внутри того же цикла — примерно раз в тридцать секунд при keepalive раз в десять, то
// есть впритык под DeadMS в сорок пять. Это не запас, это совпадение.
//
// С O_NONBLOCK пустая очередь даёт EAGAIN, цикл выходит по своей же ветке ошибки, и maintain
// получает свои сто миллисекунд. Ровно так же сделано у TUN (tun/tun_linux.go) — там
// неблокирующее чтение введено осознанно и ради пачек.
func OpenRawListen(port uint16, mask, id uint16) (Raw, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_NONBLOCK, unix.IPPROTO_TCP)
	if err != nil {
		if err == unix.EPERM {
			return nil, fmt.Errorf("сырой сокет запрещён: нужен root или CAP_NET_RAW")
		}
		return nil, fmt.Errorf("сырой сокет: %w", err)
	}
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<21)
	if err := filterPortShard(fd, port, mask, id); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &rawLinux{fd: fd}, nil
}

// SendTo отправляет готовый сегмент по адресу, которому мы не подключены. Нужно ровно для одного
// случая — RST тому, чьей сессии у нас нет: заводить под это соединение было бы дороже, чем сам
// ответ.
func (r *rawLinux) SendTo(seg []byte, daddr [4]byte) error {
	return unix.Sendto(r.fd, seg, unix.MSG_NOSIGNAL, &unix.SockaddrInet4{Addr: daddr})
}

// filterNone — глухой фильтр: не принимать ничего.
func filterNone(fd int) error {
	prog := []unix.SockFilter{{Code: unix.BPF_RET | unix.BPF_K, K: 0}}
	p := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &p)
}

// filterPortShard — только сегменты, адресованные port, у которых (sport & mask) == id.
//
// Порядок проверок не случаен: сначала порт назначения (он отбивает основную массу чужого), потом
// раскладка. Ядро исполняет фильтр на КАЖДЫЙ локально доставляемый сегмент TCP, и лишняя
// инструкция здесь — это работа на всём трафике машины.
func filterPortShard(fd int, port, mask, id uint16) error {
	var prog []unix.SockFilter
	if mask == 0 {
		prog = []unix.SockFilter{
			{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0}, // X = ihl
			{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2},  // tcp dport
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(port), Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0xFFFFFFFF},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0},
		}
	} else {
		prog = []unix.SockFilter{
			{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0}, // X = ihl
			{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2},  // tcp dport
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(port), Jf: 4},
			{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 0}, // tcp sport
			{Code: unix.BPF_ALU | unix.BPF_AND | unix.BPF_K, K: uint32(mask)},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(id), Jf: 1},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0xFFFFFFFF},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0},
		}
	}
	p := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if err := unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &p); err != nil {
		return fmt.Errorf("фильтр-раскладка не встал: %w", err)
	}
	return nil
}

// GuardUpServer — правило против RST собственного ядра для СЛУШАЮЩЕЙ стороны: гасим RST, уходящий
// с нашего порта кому угодно (клиентов много и заранее они неизвестны).
//
// Имя цепочки включает порт: два хаба на разных портах не должны снимать правила друг друга. В
// движке на C это уже стоило упавшего туннеля — второй экземпляр при выходе снимал цепочку
// первого, и тот оставался работать без защиты.
func GuardUpServer(port int) (*Guard, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("нет nft: правило против RST собственного ядра не встанет")
	}
	g := &Guard{chain: fmt.Sprintf("x_srv%d", port)}
	if err := nft("add", "table", "inet", "steer_obfs"); err != nil {
		return nil, err
	}
	_ = nft("delete", "chain", "inet", "steer_obfs", g.chain)
	if err := nft("add", "chain", "inet", "steer_obfs", g.chain,
		"{ type filter hook output priority raw; policy accept; }"); err != nil {
		return nil, err
	}
	return g, nft("add", "rule", "inet", "steer_obfs", g.chain,
		"tcp", "sport", strconv.Itoa(port),
		"tcp", "flags", "&", "rst", "==", "rst",
		"tcp", "window", "0", "counter", "drop")
}
