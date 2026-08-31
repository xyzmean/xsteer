package conf

import (
	"strings"
	"testing"
)

const (
	privB64 = "6Gtidge6FqhO/0LhrAWpRiyYaKdLZF/gib/HePLC9GU="
	pubB64  = "QYkH5bWOsEOCgIMldHPATSG7yvNyJ8st7o/HMelWKxs="
)

func mustKey(t *testing.T, s string) [32]byte {
	t.Helper()
	k, err := KeyDecode(s)
	if err != nil {
		t.Fatalf("ключ %q: %v", s, err)
	}
	return k
}

// TestСсылкаИФайлОдноИТоЖе — главное свойство: ссылка и файл описывают одну конфигурацию.
//
// Проверяется не «ссылка разобралась», а РАВЕНСТВО результата разбору файла с тем же смыслом. Иначе
// два представления начали бы расходиться по мелочам (умолчание keepalive, порядок префиксов,
// длина маски), и «настроено» зависело бы от того, чем настраивали.
func TestСсылкаИФайлОдноИТоЖе(t *testing.T) {
	file := `[Interface]
PrivateKey = ` + privB64 + `
Address    = 10.77.0.2/24
SNI        = www.microsoft.com

[Peer]
PublicKey  = ` + pubB64 + `
AllowedIPs = 10.77.0.0/24, 192.168.9.0/24
Endpoint   = 203.0.113.7:443
PersistentKeepalive = 25
`
	cf, sf, err := Parse([]byte(file), RoleSpoke)
	if err != nil {
		t.Fatalf("файл: %v", err)
	}
	link := "xs://" + KeyEncodeURL(mustKey(t, privB64)) + "@203.0.113.7:443" +
		"?pk=" + KeyEncodeURL(mustKey(t, pubB64)) +
		"&ip=10.77.0.2/24&allowed=10.77.0.0/24,192.168.9.0/24&sni=www.microsoft.com&ka=25#дом"
	cl, sl, name, err := ParseLink(link, RoleSpoke)
	if err != nil {
		t.Fatalf("ссылка: %v", err)
	}
	if name != "дом" {
		t.Errorf("имя из фрагмента: %q", name)
	}
	if sf.Priv != sl.Priv {
		t.Error("приватные ключи разошлись")
	}
	if cf.Addr != cl.Addr || cf.AddrPlen != cl.AddrPlen || cf.SNI != cl.SNI || cf.MTU != cl.MTU {
		t.Errorf("интерфейс разошёлся:\n файл: %+v\n ссылка: %+v", cf, cl)
	}
	if len(cl.Peers) != 1 || cf.Peers[0].Pub != cl.Peers[0].Pub ||
		cf.Peers[0].Endpoint != cl.Peers[0].Endpoint ||
		cf.Peers[0].EndpointPort != cl.Peers[0].EndpointPort ||
		cf.Peers[0].Keepalive != cl.Peers[0].Keepalive {
		t.Errorf("пир разошёлся:\n файл: %+v\n ссылка: %+v", cf.Peers[0], cl.Peers[0])
	}
	if len(cf.Peers[0].Allowed) != len(cl.Peers[0].Allowed) {
		t.Fatalf("префиксов: файл %d, ссылка %d", len(cf.Peers[0].Allowed), len(cl.Peers[0].Allowed))
	}
	for i := range cf.Peers[0].Allowed {
		if cf.Peers[0].Allowed[i] != cl.Peers[0].Allowed[i] {
			t.Errorf("префикс %d разошёлся: %+v против %+v", i,
				cf.Peers[0].Allowed[i], cl.Peers[0].Allowed[i])
		}
	}
}

// TestСсылкаКругом — Link и ParseLink обратны друг другу.
func TestСсылкаКругом(t *testing.T) {
	file := `[Interface]
PrivateKey = ` + privB64 + `
Address    = 10.77.0.5/24
MTU        = 1400
DNS        = 10.77.0.1

[Peer]
PublicKey  = ` + pubB64 + `
AllowedIPs = 0.0.0.0/0
Endpoint   = 198.51.100.9:8443
PersistentKeepalive = 0
`
	c, s, err := Parse([]byte(file), RoleSpoke)
	if err != nil {
		t.Fatalf("файл: %v", err)
	}
	link, err := Link(c, s, "узел один")
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	c2, s2, name, err := ParseLink(link, RoleSpoke)
	if err != nil {
		t.Fatalf("ParseLink(%s): %v", link, err)
	}
	if name != "узел один" {
		t.Errorf("имя: %q", name)
	}
	if s.Priv != s2.Priv {
		t.Error("ключ не тот")
	}
	// PersistentKeepalive = 0 ОБЯЗАН пережить круг: ноль означает «выключено», а потеря признака
	// превратила бы его в умолчание 25 — то есть выключенный keepalive включился бы сам.
	if c2.Peers[0].Keepalive != 0 || !c2.Peers[0].KeepaliveSet {
		t.Errorf("ka=0 не пережил круг: Keepalive=%d Set=%v",
			c2.Peers[0].Keepalive, c2.Peers[0].KeepaliveSet)
	}
	if c2.MTU != 1400 || len(c2.DNS) != 1 || c2.DNS[0] != "10.77.0.1" {
		t.Errorf("mtu или dns не пережили круг: %+v", c2)
	}
	if c2.Peers[0].Allowed[0].Plen != 0 {
		t.Errorf("полный туннель не пережил круг: %+v", c2.Peers[0].Allowed)
	}
	// И ещё раз: ссылка из разобранной ссылки обязана совпасть побайтово.
	link2, err := Link(c2, s2, name)
	if err != nil {
		t.Fatal(err)
	}
	if link != link2 {
		t.Errorf("второй круг дал другую ссылку:\n%s\n%s", link, link2)
	}
}

// TestСсылкаБезAllowed — умолчание для allowed это СЕТЬ ИЗ ip, а не полный туннель.
//
// Выбор в безопасную сторону, и это решение, а не удобство: полный туннель — воля человека, а не то,
// что случается от краткости ссылки.
func TestСсылкаБезAllowed(t *testing.T) {
	link := "xs://" + KeyEncodeURL(mustKey(t, privB64)) + "@203.0.113.7:443?pk=" +
		KeyEncodeURL(mustKey(t, pubB64)) + "&ip=10.77.0.2/24"
	c, s, _, err := ParseLink(link, RoleSpoke)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer s.Wipe()
	a := c.Peers[0].Allowed
	if len(a) != 1 || a[0].Plen != 24 || a[0].Net != 10<<24|77<<16|0<<8|0 {
		t.Fatalf("умолчание allowed: %+v", a)
	}
}

// TestСсылкаОтвергает — разбор строгий, как у файла: каждая из этих ссылок обязана быть отвергнута
// С ОБЪЯСНЕНИЕМ, а не принята молча. Принятая молча опечатка означает «настроено» без настройки.
func TestСсылкаОтвергает(t *testing.T) {
	base := "xs://" + KeyEncodeURL(mustKey(t, privB64)) + "@203.0.113.7:443?pk=" +
		KeyEncodeURL(mustKey(t, pubB64)) + "&ip=10.77.0.2/24"
	cases := []struct{ name, link, want string }{
		{"чужая схема", strings.Replace(base, "xs://", "vless://", 1), "не xs"},
		{"нет ключа", "xs://203.0.113.7:443?pk=x", "приватного ключа"},
		{"короткий ключ", "xs://abc@203.0.113.7:443?pk=x&ip=10.0.0.1/24", "приватный ключ"},
		{"нет pk", "xs://" + KeyEncodeURL(mustKey(t, privB64)) +
			"@203.0.113.7:443?ip=10.77.0.2/24", "нет pk"},
		{"нет ip", "xs://" + KeyEncodeURL(mustKey(t, privB64)) +
			"@203.0.113.7:443?pk=" + KeyEncodeURL(mustKey(t, pubB64)), "нет ip"},
		{"опечатка в параметре", base + "&snii=a", "неизвестный параметр"},
		{"повтор параметра", base + "&sni=a&sni=b", "задан 2 раза"},
		{"имя вместо адреса", "xs://" + KeyEncodeURL(mustKey(t, privB64)) +
			"@example.com:443?pk=" + KeyEncodeURL(mustKey(t, pubB64)) + "&ip=10.0.0.1/24", "IPv4"},
		{"порт вне предела", "xs://" + KeyEncodeURL(mustKey(t, privB64)) +
			"@203.0.113.7:99999?pk=" + KeyEncodeURL(mustKey(t, pubB64)) + "&ip=10.0.0.1/24", "порт"},
		{"адрес IPv6 внутри", base[:strings.Index(base, "&ip=")] + "&ip=fd00::1/64", "IPv4"},
		{"лишний путь", "xs://" + KeyEncodeURL(mustKey(t, privB64)) +
			"@203.0.113.7:443/hello?pk=" + KeyEncodeURL(mustKey(t, pubB64)) + "&ip=10.0.0.1/24",
			"лишний путь"},
		{"ссылка как конфигурация хаба", base, ""}, // проверяется отдельно ниже по роли
	}
	for _, c := range cases {
		if c.want == "" {
			continue
		}
		_, _, _, err := ParseLink(c.link, RoleSpoke)
		if err == nil {
			t.Errorf("%s: принято молча (%s)", c.name, c.link)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: отказ не про то — %v (ждали упоминание %q)", c.name, err, c.want)
		}
	}
	// Роль хаба отвергается ОБЪЯСНЕНИЕМ, а не общей ошибкой разбора: человек должен узнать, что
	// хаб настраивается файлом, а не что «ссылка неверна».
	if _, _, _, err := ParseLink(base, RoleHub); err == nil ||
		!strings.Contains(err.Error(), "хаб настраивается файлом") {
		t.Errorf("ссылка для роли хаба: %v", err)
	}
}

// TestКлючВСсылкеОбаАлфавита — на разборе принимаются и base64url, и обычный base64 с набивкой:
// человек вставляет ключ прямо из wg-конфигурации.
func TestКлючВСсылкеОбаАлфавита(t *testing.T) {
	want := mustKey(t, privB64)
	for _, s := range []string{
		KeyEncodeURL(want),
		privB64,
		strings.TrimRight(privB64, "="),
	} {
		got, err := KeyDecodeURL(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got != want {
			t.Fatalf("%q дал другой ключ", s)
		}
	}
	// А вот мусор той же длины — отказ: у одного ключа не должно быть нескольких написаний.
	for _, s := range []string{"", "x", strings.Repeat("A", 42), strings.Repeat("!", 43)} {
		if _, err := KeyDecodeURL(s); err == nil {
			t.Errorf("%q принят как ключ", s)
		}
	}
}
