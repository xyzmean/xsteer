package conf

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// ССЫЛКА xs:// — та же конфигурация, но в одну строку.
//
// ЗАЧЕМ. Файл в стиле wg хорош там, где его пишут руками, и плох там, где его передают: в
// сообщении, в QR-коде, в поле ввода на странице. Ссылка решает ровно эту задачу и ничего кроме —
// формат ссылки и формат файла описывают ОДНО И ТО ЖЕ, разбираются в одну структуру и проверяются
// одними правилами. Никакой возможности задать ссылкой то, чего нельзя задать файлом, нет и не
// будет: два представления с разными возможностями — это два разных понятия «настроено».
//
// ВИД:
//
//	xs://<приватный ключ пира>@<хост>:<порт>?pk=<публичный ключ хаба>&ip=<адрес/длина>#<имя>
//
// Полный набор параметров:
//
//	pk       публичный ключ хаба (обязателен)
//	ip       адрес внутри туннеля с длиной префикса, например 10.77.0.2/24 (обязателен)
//	allowed  префиксы AllowedIPs через запятую; по умолчанию — сеть из ip
//	sni      имя, которым прикрывается рукопожатие
//	mtu      предел туннеля; по умолчанию выводится из MTU канала
//	ka       PersistentKeepalive в секундах; ka=0 ВЫКЛЮЧАЕТ его, отсутствие ключа даёт умолчание 25
//	dns      серверы имён через запятую
//
// Имя после решётки — только для человека: в конфигурации поля «имя» нет, и разбор его лишь
// возвращает вызывающему для показа.
//
// КЛЮЧИ В ССЫЛКЕ — base64url БЕЗ НАБИВКИ (43 символа, алфавит с '-' и '_'), потому что обычный
// base64 содержит '+' и '/', а им в ссылке нужна процентная запись — и ссылка становится
// нечитаемой и ломается при копировании через мессенджеры. На РАЗБОРЕ принимаются оба алфавита и
// набивка необязательна: человек будет вставлять ключ и прямо из wg-конфигурации.
//
// РАЗБОР СТРОГИЙ, как и у файла. Неизвестный параметр — отказ с подсказкой, а не «запас на будущее»:
// опечатка в имени параметра, принятая молча, означает «настроено» без настройки. Повтор параметра —
// тоже отказ: «последний победил» здесь означало бы, что смысл ссылки зависит от того, как её
// склеили.
//
// В ССЫЛКЕ ЛЕЖИТ ПРИВАТНЫЙ КЛЮЧ. Это не оплошность формата, а его суть: ссылка и есть выданный
// доступ, целиком. Отсюда два следствия, о которых сказано в справке командной строки: ссылку нельзя
// пересылать открытым каналом, и её нельзя передавать аргументом команды на многопользовательской
// машине — аргументы видны в списке процессов. Для второго есть чтение со стандартного ввода.
const LinkScheme = "xs"

// LinkMaxLen — предел длины ссылки. Шестнадцать килобайт: столько же, сколько у файла (ConfMax), и
// по той же причине — разбирать частично нельзя, а без предела строка из недоверенного источника
// становится способом занять память.
const LinkMaxLen = ConfMax

// ParseLink разбирает ссылку xs:// в ту же структуру, что и файл. Третье возвращаемое значение —
// имя из фрагмента (может быть пустым).
func ParseLink(s string, role Role) (*Conf, *Secrets, string, error) {
	if len(s) > LinkMaxLen {
		return nil, nil, "", fmt.Errorf("ссылка длиннее %d КиБ", LinkMaxLen/1024)
	}
	// Пробелы и переводы строк по краям — обычное дело при копировании из сообщения.
	s = strings.Trim(s, " \t\r\n")
	if role == RoleHub {
		// Ссылкой описывается ОДИН доступ: свой ключ, один хаб, свой адрес. Конфигурация хаба — это
		// список пиров, и уложить его в ссылку значило бы завести второй формат с другими
		// возможностями. Сказано прямо, чтобы «хаб по ссылке» не выглядел недоделкой.
		return nil, nil, "", fmt.Errorf("ссылка описывает доступ ОДНОГО пира, а хабу нужен список " +
			"пиров — хаб настраивается файлом")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ссылка не разобралась: %w", err)
	}
	if !strings.EqualFold(u.Scheme, LinkScheme) {
		return nil, nil, "", fmt.Errorf("ссылка не xs:// (схема %q)", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, nil, "", fmt.Errorf("в ссылке нет приватного ключа: он идёт перед знаком @, " +
			"как xs://<ключ>@<хост>:<порт>?...")
	}
	if _, hasPass := u.User.Password(); hasPass {
		return nil, nil, "", fmt.Errorf("в ссылке двоеточие перед @ — приватный ключ идёт один, " +
			"без пароля")
	}
	if p := strings.Trim(u.Path, "/"); p != "" {
		return nil, nil, "", fmt.Errorf("в ссылке лишний путь %q — после порта идёт сразу ?", p)
	}

	c := &Conf{}
	sec := &Secrets{}
	priv, err := KeyDecodeURL(u.User.Username())
	if err != nil {
		return nil, nil, "", fmt.Errorf("приватный ключ в ссылке: %w", err)
	}
	c.Peers = []Peer{{}}
	pe := &c.Peers[0]
	sec.Priv, sec.HasPriv = priv, true

	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, nil, "", fmt.Errorf("после @ нужен хост и порт (%s): %v", u.Host, err)
	}
	// Только литерал IPv4, ровно как в Endpoint файла и по той же причине: имя пришлось бы
	// разрешать через DNS, а он сам может быть направлен в этот же туннель.
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return nil, nil, "", fmt.Errorf("хост %q — нужен адрес IPv4 литералом: имя разрешает тот, "+
			"кто пишет ссылку, иначе туннель может зависеть от DNS внутри себя", host)
	}
	pn, err := strconv.Atoi(port)
	if err != nil || pn < 1 || pn > 65535 {
		return nil, nil, "", fmt.Errorf("порт %q — нужно число от 1 до 65535", port)
	}
	pe.Endpoint = ip.String()
	pe.EndpointPort = pn

	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, nil, "", fmt.Errorf("параметры ссылки не разобрались: %w", err)
	}
	var allowed string
	for k, vs := range q {
		if len(vs) > 1 {
			return nil, nil, "", fmt.Errorf("параметр %s задан %d раза — какое значение верное, "+
				"ссылка не говорит", k, len(vs))
		}
		v := strings.TrimSpace(vs[0])
		if v == "" {
			return nil, nil, "", fmt.Errorf("у параметра %s нет значения", k)
		}
		switch strings.ToLower(k) {
		case "pk":
			if pe.Pub, err = KeyDecodeURL(v); err != nil {
				return nil, nil, "", fmt.Errorf("pk (публичный ключ хаба): %w", err)
			}
		case "ip":
			pfx, err := netip.ParsePrefix(v)
			if err != nil || !pfx.Addr().Is4() {
				return nil, nil, "", fmt.Errorf("ip=%q — нужен адрес IPv4 с длиной префикса, "+
					"например 10.77.0.2/24", v)
			}
			c.Addr = be32(pfx.Addr().As4())
			c.AddrPlen = pfx.Bits()
		case "allowed":
			allowed = v
		case "sni":
			c.SNI = v
		case "mtu":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, nil, "", fmt.Errorf("mtu=%q — нужно число", v)
			}
			c.MTU = n
		case "ka":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 65535 {
				return nil, nil, "", fmt.Errorf("ka=%q — нужны секунды от 0 до 65535 (0 выключает)", v)
			}
			// Признак «ключ был» ставится и при нуле: ka=0 означает «выключить», а отсутствие
			// параметра — «поставь умолчание». Разница та же, что у PersistentKeepalive в файле.
			pe.Keepalive, pe.KeepaliveSet = n, true
		case "dns":
			for _, d := range strings.Split(v, ",") {
				d = strings.TrimSpace(d)
				if d == "" {
					continue
				}
				a, err := netip.ParseAddr(d)
				if err != nil || !a.Is4() {
					return nil, nil, "", fmt.Errorf("dns=%q: %q — нужен адрес IPv4", v, d)
				}
				c.DNS = append(c.DNS, a.String())
			}
		default:
			return nil, nil, "", fmt.Errorf("неизвестный параметр %s%s (есть pk, ip, allowed, "+
				"sni, mtu, ka, dns)", k, didYouMeanLink(k))
		}
	}
	if pe.Pub == ([32]byte{}) {
		return nil, nil, "", fmt.Errorf("в ссылке нет pk — публичного ключа хаба")
	}
	if c.AddrPlen == 0 && c.Addr == 0 {
		return nil, nil, "", fmt.Errorf("в ссылке нет ip — адреса внутри туннеля")
	}
	// AllowedIPs по умолчанию — СЕТЬ ИЗ ip, а не 0.0.0.0/0.
	//
	// Умолчание выбрано осознанно и в безопасную сторону: полный туннель — это решение человека, а
	// не то, что должно случаться от краткости ссылки. Сеть из ip — ровно то, что стоит в примере
	// конфигурации, то есть «вижу свою звезду»; полный туннель задаётся явным allowed=0.0.0.0/0.
	if allowed == "" {
		pfx, err := netip.ParsePrefix(fmt.Sprintf("%d.%d.%d.%d/%d",
			byte(c.Addr>>24), byte(c.Addr>>16), byte(c.Addr>>8), byte(c.Addr), c.AddrPlen))
		if err != nil {
			return nil, nil, "", fmt.Errorf("ip не разобрался обратно: %v", err)
		}
		allowed = pfx.Masked().String()
	}
	for _, a := range strings.Split(allowed, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if len(pe.Allowed) >= AllowedMax {
			return nil, nil, "", fmt.Errorf("в allowed больше %d префиксов", AllowedMax)
		}
		al, ok := parsePfx(a)
		if !ok {
			return nil, nil, "", fmt.Errorf("allowed: %q — нужен префикс IPv4, например 10.77.0.0/24", a)
		}
		pe.Allowed = append(pe.Allowed, al)
	}

	// Дальше — ТЕ ЖЕ проверки, что у файла, и они не переписаны здесь заново: ссылка собирается в
	// текст конфигурации и разбирается общим разбором. Так исключено расхождение «ссылка приняла то,
	// что файл отвергает» — самый неприятный вид разницы между двумя представлениями одного
	// понятия.
	text, err := render(c, sec)
	if err != nil {
		return nil, nil, "", err
	}
	c2, s2, err := Parse([]byte(text), role)
	if err != nil {
		return nil, nil, "", fmt.Errorf("ссылка разобрана, но конфигурация из неё не проходит "+
			"проверку: %w", err)
	}
	sec.Wipe()
	name := u.Fragment
	return c2, s2, name, nil
}

// Link печатает конфигурацию пира одной строкой xs://.
//
// Печатается СВОЙ приватный ключ, поэтому вызывающий обязан знать, что отдаёт наружу: см. шапку
// файла. Функция не решает за него — она лишь отказывается печатать ссылку, в которой ключа нет,
// потому что такая ссылка выглядела бы готовой к выдаче, не будучи ею.
func Link(c *Conf, s *Secrets, name string) (string, error) {
	if c == nil || s == nil || !s.HasPriv {
		return "", fmt.Errorf("для ссылки нужен приватный ключ пира")
	}
	if c.ListenPort != 0 {
		return "", fmt.Errorf("это конфигурация хаба (есть ListenPort) — ссылка описывает доступ " +
			"одного пира")
	}
	if len(c.Peers) != 1 {
		return "", fmt.Errorf("в ссылку укладывается ровно один пир — хаб, а секций [Peer] %d",
			len(c.Peers))
	}
	pe := &c.Peers[0]
	if pe.EndpointPort == 0 {
		return "", fmt.Errorf("у хаба нет Endpoint — по такой ссылке подключаться некуда")
	}
	var b strings.Builder
	b.WriteString(LinkScheme)
	b.WriteString("://")
	b.WriteString(KeyEncodeURL(s.Priv))
	b.WriteByte('@')
	b.WriteString(pe.Endpoint)
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(pe.EndpointPort))
	// Параметры пишутся СВОИМ порядком и своим escape, а не url.Values.Encode(), и обе причины
	// про человека. Порядок стандартной функции алфавитный (allowed, ip, ka, pk, sni) — то есть
	// самое главное, ключ хаба, оказывается в середине; здесь порядок смысловой. А escape у неё
	// излишний: '/' в строке запроса законен (RFC 3986, query = *(pchar / "/" / "?")), но она
	// печатает его как %2F, и префиксы превращаются в 10.77.0.0%2F24 — ссылку становится
	// невозможно прочесть глазами, а именно глазами её и проверяют перед выдачей.
	var al []string
	for _, a := range pe.Allowed {
		al = append(al, fmt.Sprintf("%d.%d.%d.%d/%d",
			byte(a.Net>>24), byte(a.Net>>16), byte(a.Net>>8), byte(a.Net), a.Plen))
	}
	pairs := [][2]string{
		{"pk", KeyEncodeURL(pe.Pub)},
		{"ip", fmt.Sprintf("%d.%d.%d.%d/%d",
			byte(c.Addr>>24), byte(c.Addr>>16), byte(c.Addr>>8), byte(c.Addr), c.AddrPlen)},
		// allowed печатается ВСЕГДА, даже когда совпадает с умолчанием: ссылка обязана значить одно
		// и то же независимо от того, каким умолчанием её прочтут. Умолчание — удобство для того,
		// кто пишет ссылку руками, а не для того, кто её печатает.
		{"allowed", strings.Join(al, ",")},
	}
	if c.SNI != "" {
		pairs = append(pairs, [2]string{"sni", c.SNI})
	}
	if c.MTU != 0 {
		pairs = append(pairs, [2]string{"mtu", strconv.Itoa(c.MTU)})
	}
	if pe.KeepaliveSet || pe.Keepalive != 0 {
		pairs = append(pairs, [2]string{"ka", strconv.Itoa(pe.Keepalive)})
	}
	if len(c.DNS) > 0 {
		pairs = append(pairs, [2]string{"dns", strings.Join(c.DNS, ",")})
	}
	for i, kv := range pairs {
		if i == 0 {
			b.WriteByte('?')
		} else {
			b.WriteByte('&')
		}
		b.WriteString(kv[0])
		b.WriteByte('=')
		b.WriteString(qesc(kv[1]))
	}
	if name != "" {
		b.WriteByte('#')
		// Имя в фрагменте: кодируется, потому что там бывают пробелы и кириллица.
		b.WriteString(url.PathEscape(name))
	}
	return b.String(), nil
}

// render собирает текст конфигурации из разобранной ссылки. Нужен ровно для того, чтобы ссылку
// проверял ОБЩИЙ разбор, а не своя копия правил, — см. объяснение в ParseLink.
func render(c *Conf, s *Secrets) (string, error) {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	b.WriteString("PrivateKey = " + KeyEncode(s.Priv) + "\n")
	fmt.Fprintf(&b, "Address = %d.%d.%d.%d/%d\n",
		byte(c.Addr>>24), byte(c.Addr>>16), byte(c.Addr>>8), byte(c.Addr), c.AddrPlen)
	if c.SNI != "" {
		b.WriteString("SNI = " + c.SNI + "\n")
	}
	if c.MTU != 0 {
		fmt.Fprintf(&b, "MTU = %d\n", c.MTU)
	}
	if len(c.DNS) > 0 {
		b.WriteString("DNS = " + strings.Join(c.DNS, ", ") + "\n")
	}
	pe := &c.Peers[0]
	b.WriteString("\n[Peer]\n")
	b.WriteString("PublicKey = " + KeyEncode(pe.Pub) + "\n")
	var al []string
	for _, a := range pe.Allowed {
		al = append(al, fmt.Sprintf("%d.%d.%d.%d/%d",
			byte(a.Net>>24), byte(a.Net>>16), byte(a.Net>>8), byte(a.Net), a.Plen))
	}
	if len(al) == 0 {
		return "", fmt.Errorf("в ссылке нет ни одного префикса allowed")
	}
	b.WriteString("AllowedIPs = " + strings.Join(al, ", ") + "\n")
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", pe.Endpoint, pe.EndpointPort)
	if pe.KeepaliveSet {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", pe.Keepalive)
	}
	return b.String(), nil
}

// Render печатает конфигурацию пира ФАЙЛОМ. Пара к Link: ссылку часто надо превратить в файл (её
// прислали, а держать доступ хочется в /etc), и наоборот.
func Render(c *Conf, s *Secrets) (string, error) { return render(c, s) }

// qesc — процентная запись ТОЛЬКО того, что в строке запроса значимо: '&' и '=' разделяют
// параметры, '#' начинает фрагмент, '%' начинает саму запись, '+' в строке запроса читается как
// пробел. Всё остальное печатается как есть — см. объяснение в Link.
func qesc(v string) string {
	const safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~/:,"
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if strings.IndexByte(safe, v[i]) >= 0 {
			b.WriteByte(v[i])
			continue
		}
		fmt.Fprintf(&b, "%%%02X", v[i])
	}
	return b.String()
}

func be32(a [4]byte) uint32 {
	return uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
}

// didYouMeanLink — подсказка по опечатке в имени параметра, тем же расстоянием, что у ключей файла.
func didYouMeanLink(key string) string {
	best, bd := "", 3
	for _, k := range []string{"pk", "ip", "allowed", "sni", "mtu", "ka", "dns"} {
		if d := lev(strings.ToLower(key), k); d < bd {
			best, bd = k, d
		}
	}
	if best == "" {
		return ""
	}
	return ", возможно " + best
}
