//go:build linux

package link

import (
	"fmt"
	"net"
	"time"

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
}

// OpenRaw открывает сырой сокет к daddr и ставит на него фильтр.
//
// ФИЛЬТР СТАВИТСЯ ДО ПЕРВОГО SYN, и это не мелочь: сырой сокет получает КОПИЮ каждого локально
// доставляемого сегмента TCP, и между socket() и настройкой фильтра очередь успевает набрать
// чужого — на нагруженной машине это тысячи пакетов, из-за которых теряются настоящие.
func OpenRaw(daddr [4]byte, sport, dport uint16) (Raw, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
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
		if err == unix.EINTR {
			continue
		}
		return err
	}
}

func (r *rawLinux) Recv(buf []byte) (int, error) {
	for {
		n, err := unix.Read(r.fd, buf)
		if err == unix.EINTR {
			continue
		}
		return n, err
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
