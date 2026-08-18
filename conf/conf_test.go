// Случаи те же, что в tests/xsconfmatch.c движка на C: один и тот же файл конфигурации
// человек носит между роутером и десктопом, и «принят» не должно зависеть от того, куда его
// положили.
package conf

import (
	"fmt"
	"strings"
	"testing"
)

const (
	keyA = "8BT4UvilnYyF0j+Gt5uy/oMUqH9NYOg3TrKQ/NS59lw="
	keyB = "pvlciAMuJnL06ZXI5X0LgBaeA5Zty5OsqNaE7ikzaUg="
	keyC = "wV7Mq97eNztdlcuPBmmbxETDqVTOu98cyZPfI3caKlw="
)

func mustParse(t *testing.T, text string, role Role) (*Conf, *Secrets) {
	t.Helper()
	c, s, err := Parse([]byte(text), role)
	if err != nil {
		t.Fatalf("файл обязан был приняться, а отказ: %v", err)
	}
	return c, s
}

func refuses(t *testing.T, what, text string, role Role) string {
	t.Helper()
	_, _, err := Parse([]byte(text), role)
	if err == nil {
		t.Errorf("%s: принято, а ждали отказ", what)
		return ""
	}
	return err.Error()
}

func TestКлюч(t *testing.T) {
	k, err := KeyDecode(keyA)
	if err != nil {
		t.Fatalf("честный ключ отвергнут: %v", err)
	}
	if KeyEncode(k) != keyA {
		t.Error("круг decode → encode не сошёлся")
	}
	bad := []struct{ what, s string }{
		{"без выравнивающего '='", keyA[:43] + "A"},
		{"43 символа", keyA[:43]},
		{"45 символов", keyA + "="},
		{"чужой символ", "!" + keyA[1:]},
		{"алфавит url-safe", strings.ReplaceAll(strings.ReplaceAll(keyA, "+", "-"), "/", "_")},
	}
	for _, c := range bad {
		if _, err := KeyDecode(c.s); err == nil {
			t.Errorf("ключ %s принят — молча принятый короткий ключ это тихо ослабленная криптография", c.what)
		}
	}
	// Лишние биты в хвосте: у одного ключа не должно быть четырёх написаний.
	if _, err := KeyDecode(keyA[:42] + "x="); err == nil {
		t.Error("ключ с ненулевыми лишними битами принят")
	}
	if fp := KeyFP(k); len(fp) != 8 || fp != keyA[:8] {
		t.Errorf("отпечаток = %q", fp)
	}
}

const spokeGood = `# пир на десктопе
[Interface]
PrivateKey = ` + keyA + `
Address = 10.77.0.2/24
SNI = www.microsoft.com

[Peer]
PublicKey = ` + keyB + `
AllowedIPs = 10.77.0.0/24, 192.168.88.0/24
Endpoint = 203.0.113.7:443
PersistentKeepalive = 15
`

func TestПирПринят(t *testing.T) {
	c, s := mustParse(t, spokeGood, RoleSpoke)
	if !s.HasPriv {
		t.Fatal("приватный ключ не прочитан")
	}
	want, _ := KeyDecode(keyA)
	if s.Priv != want {
		t.Error("приватный ключ прочитан не тот")
	}
	if c.Addr != 0x0A4D0002 {
		t.Errorf("адрес = %08x", c.Addr)
	}
	if c.AddrPlen != 24 {
		t.Errorf("длина префикса адреса = %d", c.AddrPlen)
	}
	if c.SNI != "www.microsoft.com" {
		t.Errorf("SNI = %q", c.SNI)
	}
	if len(c.Peers) != 1 {
		t.Fatalf("пиров %d", len(c.Peers))
	}
	pub, _ := KeyDecode(keyB)
	if c.Peers[0].Pub != pub {
		t.Error("публичный ключ пира не тот")
	}
	if len(c.Peers[0].Allowed) != 2 {
		t.Fatalf("префиксов %d", len(c.Peers[0].Allowed))
	}
	if c.Peers[0].Allowed[0].Net != 0x0A4D0000 || c.Peers[0].Allowed[1].Net != 0xC0A85800 {
		t.Error("префиксы разобраны неверно")
	}
	if c.Peers[0].Endpoint != "203.0.113.7" || c.Peers[0].EndpointPort != 443 {
		t.Error("Endpoint разобран неверно")
	}
	if c.Peers[0].Keepalive != 15 {
		t.Errorf("keepalive = %d", c.Peers[0].Keepalive)
	}
	if c.ListenPort != 0 {
		t.Error("пир не слушает")
	}
	// MTU не задан — вывести из канала, а не подставить число: подставленное запретило бы
	// поднимать предел после проб, то есть тихо ухудшило бы туннель.
	if c.MTU != 0 {
		t.Errorf("MTU = %d, а обязан остаться невыясненным", c.MTU)
	}
}

func TestСекретыНеПечатаются(t *testing.T) {
	c, s := mustParse(t, spokeGood, RoleSpoke)
	out := c.JSON()
	if strings.Contains(out, keyA) {
		t.Fatal("приватный ключ попал в JSON")
	}
	if strings.Contains(out, keyA[:12]) {
		t.Fatal("в JSON попало начало приватного ключа")
	}
	if !strings.Contains(out, `"key":`) {
		t.Error("отпечаток публичного ключа обязан быть — по нему человек узнаёт пира")
	}
	s.Wipe()
	if s.Priv != ([32]byte{}) || s.HasPriv {
		t.Error("приватный ключ не затёрт")
	}
}

func TestТерпимостьКФорме(t *testing.T) {
	// CRLF (файл из Windows), любой регистр ключей, пробелы вокруг запятых.
	text := "[interface]\r\nPRIVATEKEY=" + keyA + "\r\naddress=10.0.0.2/24\r\n\r\n" +
		"[PEER]\r\npublickey=" + keyB + "\r\nALLOWEDIPS = 10.0.0.0/24 ,  192.168.1.0/24\r\n" +
		"endpoint=1.2.3.4:443\r\n"
	c, _ := mustParse(t, text, RoleSpoke)
	if c.Addr != 0x0A000002 {
		t.Errorf("адрес = %08x", c.Addr)
	}
	if len(c.Peers[0].Allowed) != 2 {
		t.Error("пробелы вокруг запятых сломали разбор списка")
	}
	// keepalive не задан — умолчание wg: пир за NAT обязан держать отображение живым.
	if c.Peers[0].Keepalive != 25 {
		t.Errorf("keepalive по умолчанию = %d, а не 25", c.Peers[0].Keepalive)
	}

	// Одинокий \r: так приходит текст из буфера обмена старых редакторов.
	c2, _, err := Parse([]byte(strings.ReplaceAll(text, "\r\n", "\r")), RoleSpoke)
	if err != nil || c2.Addr != 0x0A000002 {
		t.Errorf("одинокий CR сломал разбор: %v", err)
	}

	// Хост-биты за маской обнуляются молча, как в wg; Address без префикса — это /32.
	c3, _ := mustParse(t, "[Interface]\nPrivateKey="+keyA+"\nAddress=10.0.0.7\n"+
		"[Peer]\nPublicKey="+keyB+"\nAllowedIPs=10.9.9.9/24\nEndpoint=1.2.3.4:443\n", RoleSpoke)
	if c3.AddrPlen != 32 {
		t.Errorf("Address без префикса дал /%d", c3.AddrPlen)
	}
	if c3.Peers[0].Allowed[0].Net != 0x0A090900 {
		t.Error("хост-биты за маской не обнулены")
	}
	// Адрес устройства при этом НЕ обнуляется: это адрес, а не сеть.
	if c3.Addr != 0x0A000007 {
		t.Errorf("адрес устройства обнулён до %08x", c3.Addr)
	}

	// Комментарии обоих видов и явный ноль keepalive.
	c4, _ := mustParse(t, "; комментарий\n[Interface]\n# ещё\nPrivateKey="+keyA+
		"\nAddress=10.0.0.2/24\nMTU=1380\n[Peer]\nPublicKey="+keyB+
		"\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\nPersistentKeepalive=0\n", RoleSpoke)
	if c4.MTU != 1380 {
		t.Errorf("MTU из файла = %d", c4.MTU)
	}
	if c4.Peers[0].Keepalive != 0 {
		t.Error("явный ноль keepalive затёрт умолчанием — человек получил то, от чего отказывался")
	}
}

func TestХаб(t *testing.T) {
	text := "[Interface]\nPrivateKey=" + keyA + "\nAddress=10.0.0.1/24\nListenPort=443\n" +
		"[Peer]\nPublicKey=" + keyB + "\nAllowedIPs=10.0.0.2/32\n" +
		"[Peer]\nPublicKey=" + keyC + "\nAllowedIPs=10.0.0.3/32,192.168.5.0/24\n"
	c, _ := mustParse(t, text, RoleHub)
	if len(c.Peers) != 2 || c.ListenPort != 443 {
		t.Fatal("конфигурация хаба разобрана неверно")
	}
	if c.Peers[0].EndpointPort != 0 {
		t.Error("у пиров хаба Endpoint быть не должно")
	}
	// Хабу keepalive не подставляется: звонит пир, а не он.
	if c.Peers[0].Keepalive != 0 {
		t.Error("хабу подставлен keepalive")
	}
}

func TestОтказы(t *testing.T) {
	head := "[Interface]\nPrivateKey=" + keyA + "\nAddress=10.0.0.2/24\n"
	peer := "[Peer]\nPublicKey=" + keyB + "\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\n"

	// Ключи wg, поведение которых мы не реализуем: отказ, а не молчаливый пропуск.
	for _, k := range []string{"DNS=1.1.1.1", "Table=off", "FwMark=0x100",
		"PostUp=iptables -A FORWARD -j ACCEPT", "PreDown=echo", "SaveConfig=true"} {
		msg := refuses(t, "ключ "+k, head+k+"\n"+peer, RoleSpoke)
		if msg != "" && !strings.Contains(msg, strings.SplitN(k, "=", 2)[0]) {
			t.Errorf("отказ не называет ключ: %s", msg)
		}
	}
	refuses(t, "PresharedKey", head+peer+"PresharedKey="+keyC+"\n", RoleSpoke)

	// Опечатка обязана получить подсказку: искать её в документации человек не должен.
	msg := refuses(t, "опечатка в имени ключа", head+
		"[Peer]\nPublicKey="+keyB+"\nAllowdIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\n", RoleSpoke)
	if !strings.Contains(msg, "AllowedIPs") {
		t.Errorf("подсказки нет: %s", msg)
	}

	refuses(t, "неизвестная секция", "[Interfce]\nPrivateKey="+keyA+"\n", RoleSpoke)
	refuses(t, "ключ вне секции", "PrivateKey="+keyA+"\n", RoleSpoke)
	refuses(t, "секция без закрывающей скобки", "[Interface\nPrivateKey="+keyA+"\n", RoleSpoke)
	refuses(t, "строка без знака равенства", "[Interface]\nPrivateKey\n", RoleSpoke)
	refuses(t, "ключ без значения", "[Interface]\nPrivateKey=\n", RoleSpoke)

	refuses(t, "PrivateKey на символ короче",
		"[Interface]\nPrivateKey="+keyA[:43]+"\nAddress=10.0.0.2/24\n"+peer, RoleSpoke)
	refuses(t, "нет PrivateKey", "[Interface]\nAddress=10.0.0.2/24\n"+peer, RoleSpoke)
	refuses(t, "нет Address", "[Interface]\nPrivateKey="+keyA+"\n"+peer, RoleSpoke)
	refuses(t, "нет ни одного пира", head, RoleSpoke)

	msg = refuses(t, "IPv6 в Address", "[Interface]\nPrivateKey="+keyA+"\nAddress=fd00::2/64\n"+peer, RoleSpoke)
	if !strings.Contains(msg, "IPv4") {
		t.Errorf("отказ про IPv6 обязан назвать причину: %s", msg)
	}
	refuses(t, "длина префикса больше 32", "[Interface]\nPrivateKey="+keyA+"\nAddress=10.0.0.2/33\n"+peer, RoleSpoke)
	refuses(t, "MTU вне разумного", head+"MTU=64\n"+peer, RoleSpoke)

	msg = refuses(t, "Endpoint именем", head+
		"[Peer]\nPublicKey="+keyB+"\nAllowedIPs=0.0.0.0/0\nEndpoint=hub.example.com:443\n", RoleSpoke)
	if !strings.Contains(msg, "DNS") {
		t.Errorf("отказ обязан объяснить, почему не имя: %s", msg)
	}
	refuses(t, "Endpoint без порта", head+
		"[Peer]\nPublicKey="+keyB+"\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4\n", RoleSpoke)
	refuses(t, "Endpoint с портом 0", head+
		"[Peer]\nPublicKey="+keyB+"\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:0\n", RoleSpoke)
	refuses(t, "неразбираемый префикс", head+
		"[Peer]\nPublicKey="+keyB+"\nAllowedIPs=10.0.0.0/8,мусор\nEndpoint=1.2.3.4:443\n", RoleSpoke)
	refuses(t, "пир без AllowedIPs", head+
		"[Peer]\nPublicKey="+keyB+"\nEndpoint=1.2.3.4:443\n", RoleSpoke)
	refuses(t, "пир без PublicKey", head+
		"[Peer]\nAllowedIPs=0.0.0.0/0\nEndpoint=1.2.3.4:443\n", RoleSpoke)

	// Роль решает вызывающий, но требования проверяются здесь.
	refuses(t, "ListenPort у пира", head+"ListenPort=443\n"+peer, RoleSpoke)
	refuses(t, "у пира две секции [Peer]", head+peer+
		"[Peer]\nPublicKey="+keyC+"\nAllowedIPs=10.5.0.0/16\nEndpoint=5.6.7.8:443\n", RoleSpoke)
	refuses(t, "у пира нет Endpoint", head+"[Peer]\nPublicKey="+keyB+"\nAllowedIPs=0.0.0.0/0\n", RoleSpoke)
	refuses(t, "хаб без ListenPort", "[Interface]\nPrivateKey="+keyA+"\nAddress=10.0.0.1/24\n"+
		"[Peer]\nPublicKey="+keyB+"\nAllowedIPs=10.0.0.2/32\n", RoleHub)
	refuses(t, "Endpoint в конфигурации хаба", "[Interface]\nPrivateKey="+keyA+
		"\nAddress=10.0.0.1/24\nListenPort=443\n"+peer, RoleHub)

	// Самая ценная проверка хаба: пересечение означало бы, что пакет достаётся
	// непредсказуемому пиру, а симптом — «работает, но не туда».
	msg = refuses(t, "AllowedIPs двух пиров пересекаются", "[Interface]\nPrivateKey="+keyA+
		"\nAddress=10.0.0.1/24\nListenPort=443\n"+
		"[Peer]\nPublicKey="+keyB+"\nAllowedIPs=10.9.0.0/16\n"+
		"[Peer]\nPublicKey="+keyC+"\nAllowedIPs=10.9.5.0/24\n", RoleHub)
	if !strings.Contains(msg, "1") || !strings.Contains(msg, "2") {
		t.Errorf("отказ обязан назвать обоих пиров: %s", msg)
	}
	refuses(t, "один PublicKey у двух пиров", "[Interface]\nPrivateKey="+keyA+
		"\nAddress=10.0.0.1/24\nListenPort=443\n"+
		"[Peer]\nPublicKey="+keyB+"\nAllowedIPs=10.9.0.0/16\n"+
		"[Peer]\nPublicKey="+keyB+"\nAllowedIPs=10.8.0.0/16\n", RoleHub)
}

func TestПереполнения(t *testing.T) {
	// Отказ, а не отбрасывание лишнего: префикс, молча не попавший в таблицу, это
	// «настроено и не работает».
	var pfx []string
	for i := 0; i <= AllowedMax; i++ {
		pfx = append(pfx, fmt.Sprintf("10.%d.0.0/16", i))
	}
	refuses(t, "префиксов больше предела", "[Interface]\nPrivateKey="+keyA+
		"\nAddress=10.0.0.2/24\n[Peer]\nPublicKey="+keyB+"\nEndpoint=1.2.3.4:443\nAllowedIPs="+
		strings.Join(pfx, ",")+"\n", RoleSpoke)

	var b strings.Builder
	b.WriteString("[Interface]\nPrivateKey=" + keyA + "\nAddress=10.0.0.1/24\nListenPort=443\n")
	for i := 0; i <= PeersMax; i++ {
		// Ключи разные: иначе первым сработал бы отказ про одинаковый PublicKey, и предел
		// числа пиров остался бы непроверенным.
		var k [32]byte
		k[0], k[1] = byte(i), byte(i>>8)
		fmt.Fprintf(&b, "[Peer]\nPublicKey=%s\nAllowedIPs=10.%d.0.0/16\n", KeyEncode(k), i)
	}
	refuses(t, "пиров больше предела", b.String(), RoleHub)

	refuses(t, "файл больше предела", strings.Repeat("# набивка\n", ConfMax/10+10), RoleSpoke)
}
