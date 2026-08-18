package conf

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Пределы. Совпадают с движком на C (XS_PEERS_MAX и прочие) — конфигурация носится между
// роутером и десктопом, и файл, принятый одной реализацией и отвергнутый другой, означал бы,
// что «настроено» зависит от того, куда его положили.
const (
	// PeersMax — пиров в звезде на один хаб. Тридцать два, а не тысяча: это домашние роутеры и
	// десктопы, а поиск пира по статическому ключу линейный (зовётся раз на рукопожатие).
	// Переполнение — ОТКАЗ, а не отбрасывание лишних: пир, молча не попавший в таблицу, это
	// пир, который «настроен и не работает».
	PeersMax = 32
	// AllowedMax — префиксов на пира. Домашнему хватает двух-трёх (его сеть и адрес внутри
	// туннеля); шестнадцать — с запасом на филиал с несколькими подсетями.
	AllowedMax = 16
	// ConfMax — предел файла. Больший отвергается, а не читается частично.
	ConfMax = 16 * 1024
	// LinkMax повторяет предел канала из пакета wire; продублирован здесь, чтобы разбор не
	// зависел от него импортом: conf обязан собираться сам по себе, его читают утилиты.
	LinkMax = 1500
)

// Role — роли: хаб слушает, пир соединяется. Роль в файле не написана — её задаёт сторона,
// которая файл читает, — но разбор ОДИН, иначе получились бы два представления об одной
// сущности, и требования проверяются здесь, по роли.
type Role int

const (
	RoleSpoke Role = iota // пир: десктоп или роутер
	RoleHub               // хаб на сервере
)

// Allowed — префикс в ХОСТОВОМ порядке: маски удобнее строить и сравнивать так, а на пути
// данных это стоит одного разворота байт на пакет против шестидесяти четырёх сравнений.
// Порядок назван здесь, чтобы вопрос не возникал.
type Allowed struct {
	Net, Mask uint32
	Plen      int
}

// Peer — пир из конфигурации.
type Peer struct {
	Pub [32]byte
	// Endpoint — только литерал IPv4. Имя пришлось бы разрешать через DNS, а он сам может быть
	// направлен в этот же туннель — тогда туннель не поднимется никогда. Разрешает имя тот,
	// кто пишет файл.
	Endpoint     string
	EndpointPort int // 0 — Endpoint не задан (так у хаба: пир позвонит сам)
	Allowed      []Allowed
	Keepalive    int // секунды; 0 — выключено
	// KeepaliveSet: «нет ключа» и «PersistentKeepalive = 0» — РАЗНЫЕ вещи. Первое означает
	// «поставь умолчание», второе — «выключи». Без этого признака выключить keepalive было
	// нечем: ноль молча превращался бы в умолчание, и человек, написавший 0, получал бы ровно
	// то, от чего отказывался.
	KeepaliveSet bool
}

// Conf — всё, что можно печатать. Секретов здесь нет ни одного.
type Conf struct {
	Addr       uint32 // адрес внутри туннеля, хостовый порядок
	AddrPlen   int
	MTU        int // 0 — вывести из MTU канала
	ListenPort int // 0 — не слушать (пир)
	SNI        string
	// DNS — серверы имён, которые встают на устройство туннеля. Пусто — не трогать резолвер.
	//
	// Нужны полному туннелю: без них запросы уходят серверу физического интерфейса (обычно это
	// адрес роутера), и провайдер видит, куда человек ходит, хотя сам трафик спрятан. Применяет
	// их платформа — на Windows через winipcfg, на Linux отказ назван прямо, потому что там
	// именами распоряжается dnsmasq.
	DNS   []string
	Peers []Peer
}

// Secrets — то, что печатать нельзя никогда.
type Secrets struct {
	Priv    [32]byte
	HasPriv bool
}

// Wipe затирает приватный ключ.
//
// В Go нет volatile, и компилятор вправе выбросить запись в память, которая больше не
// читается. Поэтому затирание идёт через функцию, которая память ещё и ЧИТАЕТ (в глобальную
// переменную-приёмник): выбросить такую запись он уже не может. Приём тот же, что в C с
// volatile-указателем, и по той же причине — обещание «ключ не останется в памяти процесса»
// не должно зависеть от настроения оптимизатора.
func (s *Secrets) Wipe() {
	for i := range s.Priv {
		s.Priv[i] = 0
	}
	wipeSink += int(s.Priv[0]) | int(s.Priv[31])
	s.HasPriv = false
}

var wipeSink int

// Ключи wg, поведение которых мы не реализуем. Отвергаются НАЗЫВАЯ замену: человек,
// скопировавший конфигурацию из wg-quick, обязан узнать, что его PostUp не выполнится, —
// иначе он будет ждать от туннеля того, чего тот не делает.
var refused = []struct{ key, why string }{
	{"Table", "таблицами маршрутизации распоряжается сам клиент"},
	{"FwMark", "метку клиент выбирает сам, задать её снаружи нельзя"},
	{"PreUp", "клиент не исполняет команды из конфигурации"},
	{"PostUp", "клиент не исполняет команды из конфигурации"},
	{"PreDown", "клиент не исполняет команды из конфигурации"},
	{"PostDown", "клиент не исполняет команды из конфигурации"},
	{"SaveConfig", "клиент конфигурацию не перезаписывает"},
	{"PresharedKey", "xsteer не использует предварительный ключ: принять его молча значило бы " +
		"сказать «настроено», не настроив ничего"},
}

// Известные ключи — для подсказки при опечатке: опечатка в имени ключа не должна требовать
// чтения документации.
var known = []string{
	"PrivateKey", "Address", "MTU", "ListenPort", "SNI", "DNS",
	"PublicKey", "AllowedIPs", "Endpoint", "PersistentKeepalive",
}

func lev(a, b string) int {
	la, lb := len(a), len(b)
	if la > 32 || lb > 32 {
		return 99
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			c := 1
			if a[i-1]|32 == b[j-1]|32 {
				c = 0
			}
			m := prev[j] + 1
			if cur[j-1]+1 < m {
				m = cur[j-1] + 1
			}
			if prev[j-1]+c < m {
				m = prev[j-1] + c
			}
			cur[j] = m
		}
		copy(prev, cur)
	}
	return prev[lb]
}

func didYouMean(key string) string {
	best, bd := "", 99
	for _, k := range known {
		if d := lev(key, k); d < bd {
			bd, best = d, k
		}
	}
	if bd <= 3 {
		return best
	}
	return ""
}

func ieq(a, b string) bool { return strings.EqualFold(a, b) }

// parsePfx разбирает «10.0.0.0/24» или «1.2.3.4» (то же, что /32).
func parsePfx(s string) (Allowed, bool) {
	var a Allowed
	host, plen := s, 32
	if i := strings.IndexByte(s, '/'); i >= 0 {
		host = s[:i]
		v, err := strconv.Atoi(s[i+1:])
		if err != nil || v < 0 || v > 32 {
			return a, false
		}
		plen = v
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return a, false
	}
	v4 := ip.To4()
	// ParseIP принимает и IPv6, и «1.2.3.4» в виде ::ffff:1.2.3.4; нам нужен именно IPv4, и
	// проверка идёт по To4, а не по наличию двоеточия: адрес ::ffff:10.0.0.1 двоеточие имеет,
	// а маршрутизацией является ровно IPv4.
	if v4 == nil || strings.ContainsRune(host, ':') {
		return a, false
	}
	net32 := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	var mask uint32
	if plen > 0 {
		mask = ^uint32(0) << (32 - plen)
	}
	// Хост-биты за маской обнуляются молча, как это делает и wg: «10.0.0.5/24» человек пишет
	// чаще, чем «10.0.0.0/24», и отвергать это значило бы придираться.
	a.Net, a.Mask, a.Plen = net32&mask, mask, plen
	return a, true
}

// Parse разбирает текст конфигурации. Чистая функция: ни файлов, ни времени, ни завершения
// процесса — поэтому её и проверяет тест литералами. Это единственное место, куда в клиент
// попадает текст, написанный человеком руками.
func Parse(text []byte, role Role) (*Conf, *Secrets, error) {
	c := &Conf{}
	s := &Secrets{}
	if len(text) > ConfMax {
		return nil, nil, fmt.Errorf("файл больше %d КиБ", ConfMax/1024)
	}

	const (
		sectNone  = -1 // секции ещё не было
		sectIface = -2
	)
	inPeer := sectNone
	haveAddr := false

	// Разделяем по любому концу строки: файл приносят из Windows, из буфера обмена и
	// перетаскиванием, и все три дают разное — CRLF, LF и одинокий CR. Пустые строки при этом
	// СОХРАНЯЮТСЯ, а не схлопываются: номер строки в тексте отказа — половина его пользы, и
	// «строка 7» обязана указывать на седьмую строку файла, а не на седьмую непустую.
	norm := strings.ReplaceAll(strings.ReplaceAll(string(text), "\r\n", "\n"), "\r", "\n")
	raw := strings.Split(norm, "\n")

	for i, rawLine := range raw {
		lineNo := i + 1
		line := strings.Trim(rawLine, " \t")
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		if line[0] == '[' {
			br := strings.IndexByte(line, ']')
			if br < 0 {
				return nil, nil, fmt.Errorf("строка %d: секция без закрывающей скобки", lineNo)
			}
			name := strings.Trim(line[1:br], " \t")
			switch {
			case ieq(name, "Interface"):
				inPeer = sectIface
			case ieq(name, "Peer"):
				if len(c.Peers) >= PeersMax {
					return nil, nil, fmt.Errorf("строка %d: пиров больше %d", lineNo, PeersMax)
				}
				c.Peers = append(c.Peers, Peer{})
				inPeer = len(c.Peers) - 1
			default:
				// Неизвестная секция — отказ, а не «все её ключи неизвестны»: иначе один
				// опечатанный заголовок породил бы десяток жалоб на ключи, и настоящая причина
				// утонула бы в них.
				return nil, nil, fmt.Errorf("строка %d: неизвестная секция [%s] "+
					"(нужна [Interface] или [Peer])", lineNo, name)
			}
			continue
		}

		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			return nil, nil, fmt.Errorf("строка %d: нет знака равенства", lineNo)
		}
		key := strings.Trim(line[:eq], " \t")
		val := strings.Trim(line[eq+1:], " \t")
		if key == "" {
			return nil, nil, fmt.Errorf("строка %d: пустое имя ключа", lineNo)
		}
		if val == "" {
			return nil, nil, fmt.Errorf("строка %d: у ключа %s нет значения", lineNo, key)
		}
		if inPeer == sectNone {
			return nil, nil, fmt.Errorf("строка %d: ключ %s вне секции", lineNo, key)
		}
		for _, r := range refused {
			if ieq(key, r.key) {
				return nil, nil, fmt.Errorf("строка %d: ключ %s не поддерживается — %s",
					lineNo, r.key, r.why)
			}
		}

		if inPeer == sectIface {
			switch {
			case ieq(key, "PrivateKey"):
				k, err := KeyDecode(val)
				if err != nil {
					return nil, nil, fmt.Errorf("строка %d: PrivateKey должен быть 32 байта в "+
						"base64 (%d символа, как у wg genkey)", lineNo, KeyB64)
				}
				s.Priv, s.HasPriv = k, true
			case ieq(key, "Address"):
				// IPv6 отвергается ЯВНО. Маршрутизация клиента только про IPv4, и принять адрес
				// значило бы обещать то, чего нет: туннель поднялся бы, а трафик не пошёл.
				if strings.ContainsRune(val, ':') {
					return nil, nil, fmt.Errorf("строка %d: Address только IPv4 — "+
						"маршрутизация клиента про IPv4", lineNo)
				}
				a, ok := parsePfx(val)
				if !ok {
					return nil, nil, fmt.Errorf("строка %d: Address должен быть вида 10.0.0.2/24", lineNo)
				}
				host := val
				if i := strings.IndexByte(val, '/'); i >= 0 {
					host = val[:i]
				}
				ip := net.ParseIP(host).To4()
				if ip == nil {
					return nil, nil, fmt.Errorf("строка %d: Address не разобран", lineNo)
				}
				// Адрес берётся БЕЗ обнуления хост-битов: это адрес устройства, а не сеть.
				c.Addr = uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
				c.AddrPlen = a.Plen
				haveAddr = true
			case ieq(key, "MTU"):
				v, err := strconv.Atoi(val)
				if err != nil || v < 576 || v > LinkMax {
					return nil, nil, fmt.Errorf("строка %d: MTU вне разумного (576..%d)", lineNo, LinkMax)
				}
				c.MTU = v
			case ieq(key, "ListenPort"):
				v, err := strconv.Atoi(val)
				if err != nil || v < 1 || v > 65535 {
					return nil, nil, fmt.Errorf("строка %d: ListenPort вне 1..65535", lineNo)
				}
				c.ListenPort = v
			case ieq(key, "SNI"):
				if len(val) > 127 {
					return nil, nil, fmt.Errorf("строка %d: SNI длиннее 127 символов", lineNo)
				}
				c.SNI = val
			case ieq(key, "DNS"):
				// Только литералы адресов: имя сервера имён пришлось бы разрешать через сервер
				// имён, которого ещё нет. Разбираем здесь, а не при применении, потому что
				// опечатка в адресе обязана остановить запуск, а не всплыть предупреждением
				// уже под поднятым туннелем.
				for _, part := range strings.Split(val, ",") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					if _, err := netip.ParseAddr(part); err != nil {
						return nil, nil, fmt.Errorf("строка %d: DNS %q — нужен адрес, а не имя",
							lineNo, part)
					}
					c.DNS = append(c.DNS, part)
				}
			default:
				if h := didYouMean(key); h != "" {
					return nil, nil, fmt.Errorf("строка %d: неизвестный ключ %s — возможно, %s", lineNo, key, h)
				}
				return nil, nil, fmt.Errorf("строка %d: неизвестный ключ %s", lineNo, key)
			}
			continue
		}

		pe := &c.Peers[inPeer]
		switch {
		case ieq(key, "PublicKey"):
			k, err := KeyDecode(val)
			if err != nil {
				return nil, nil, fmt.Errorf("строка %d: PublicKey должен быть 32 байта в base64", lineNo)
			}
			pe.Pub = k
		case ieq(key, "AllowedIPs"):
			for _, item := range strings.Split(val, ",") {
				item = strings.Trim(item, " \t")
				if item == "" {
					continue
				}
				if len(pe.Allowed) >= AllowedMax {
					return nil, nil, fmt.Errorf("строка %d: префиксов у пира больше %d", lineNo, AllowedMax)
				}
				a, ok := parsePfx(item)
				if !ok {
					return nil, nil, fmt.Errorf("строка %d: AllowedIPs: не разобран префикс %s", lineNo, item)
				}
				pe.Allowed = append(pe.Allowed, a)
			}
		case ieq(key, "Endpoint"):
			colon := strings.LastIndexByte(val, ':')
			if colon < 0 {
				return nil, nil, fmt.Errorf("строка %d: Endpoint должен быть вида адрес:порт", lineNo)
			}
			port, err := strconv.Atoi(val[colon+1:])
			if err != nil || port < 1 || port > 65535 {
				return nil, nil, fmt.Errorf("строка %d: Endpoint: порт вне 1..65535", lineNo)
			}
			host := val[:colon]
			if ip := net.ParseIP(host); ip == nil || ip.To4() == nil {
				return nil, nil, fmt.Errorf("строка %d: Endpoint задаётся адресом, а не именем: "+
					"разрешение имени пошло бы через DNS, который сам может идти в этот туннель", lineNo)
			}
			pe.Endpoint, pe.EndpointPort = host, port
		case ieq(key, "PersistentKeepalive"):
			v, err := strconv.Atoi(val)
			if err != nil || v < 0 || v > 3600 {
				return nil, nil, fmt.Errorf("строка %d: PersistentKeepalive вне 0..3600", lineNo)
			}
			pe.Keepalive, pe.KeepaliveSet = v, true
		default:
			if h := didYouMean(key); h != "" {
				return nil, nil, fmt.Errorf("строка %d: неизвестный ключ %s — возможно, %s", lineNo, key, h)
			}
			return nil, nil, fmt.Errorf("строка %d: неизвестный ключ %s", lineNo, key)
		}
	}

	// ---- проверки целого файла ----
	if !s.HasPriv {
		return nil, nil, fmt.Errorf("нет PrivateKey в [Interface]")
	}
	if !haveAddr {
		return nil, nil, fmt.Errorf("нет Address в [Interface]")
	}
	if len(c.Peers) == 0 {
		return nil, nil, fmt.Errorf("нет ни одной секции [Peer]")
	}
	for i := range c.Peers {
		pe := &c.Peers[i]
		if pe.Pub == ([32]byte{}) {
			return nil, nil, fmt.Errorf("пир %d: нет PublicKey", i+1)
		}
		if len(pe.Allowed) == 0 {
			return nil, nil, fmt.Errorf("пир %d: нет AllowedIPs", i+1)
		}
		// Один и тот же публичный ключ у двух пиров — это либо копипаста, либо попытка завести
		// двух пиров с одним ключом. И то и другое означает, что трафик достанется
		// непредсказуемому из них: хаб ищет пира по ключу.
		for k := 0; k < i; k++ {
			if pe.Pub == c.Peers[k].Pub {
				return nil, nil, fmt.Errorf("пиры %d и %d: один и тот же PublicKey", k+1, i+1)
			}
		}
	}

	if role == RoleSpoke {
		if c.ListenPort != 0 {
			return nil, nil, fmt.Errorf("ListenPort — это конфигурация хаба: пир никуда не слушает")
		}
		// Две секции [Peer] у пира означали бы, что часть трафика идёт мимо хаба, а маршрут
		// пир↔пир через хаб — обещание топологии, а не деталь реализации.
		if len(c.Peers) != 1 {
			return nil, nil, fmt.Errorf("у пира ровно одна секция [Peer] — хаб; сети других " +
				"пиров задаются их префиксами в AllowedIPs этого пира")
		}
		if c.Peers[0].EndpointPort == 0 {
			return nil, nil, fmt.Errorf("единственному пиру нужен Endpoint: соединение начинает пир, а не хаб")
		}
		// Умолчание wg — 25 секунд, и оно же здесь: пир за NAT обязан поддерживать отображение
		// живым, потому что дозвониться до него хаб не может. Подставляется только когда ключа
		// НЕ БЫЛО: явный ноль означает «выключено».
		if !c.Peers[0].KeepaliveSet {
			c.Peers[0].Keepalive = 25
		}
	} else {
		if c.ListenPort == 0 {
			return nil, nil, fmt.Errorf("хабу нужен ListenPort")
		}
		for i := range c.Peers {
			if c.Peers[i].EndpointPort != 0 {
				return nil, nil, fmt.Errorf("пир %d: Endpoint в конфигурации хаба бессмыслен — "+
					"пиры живут за NAT и приходят сами", i+1)
			}
		}
		// Пересечение префиксов двух пиров ОТВЕРГАЕТСЯ, а не разрешается «последний победил»,
		// как это делает wg. На хабе неоднозначность означает молчаливый увод трафика к другому
		// пиру, и найти такое по симптому нельзя: работает, но не туда.
		for i := range c.Peers {
			for k := 0; k < i; k++ {
				for _, x := range c.Peers[i].Allowed {
					for _, y := range c.Peers[k].Allowed {
						m := x.Mask & y.Mask
						if x.Net&m == y.Net&m {
							return nil, nil, fmt.Errorf("пиры %d и %d: AllowedIPs пересекаются — "+
								"хаб не смог бы решить, кому отдать пакет", k+1, i+1)
						}
					}
				}
			}
		}
	}
	return c, s, nil
}
