package conf

import "testing"

// TestКрестСРеализациейНаC — ссылку, напечатанную половиной на C, обязана принимать эта половина, и
// наоборот, ПОБАЙТОВО одна и та же строка.
//
// Зачем отдельным стендом, если формат уже проверен в link_test.go. Там проверяется, что эта
// реализация сама себе не противоречит; здесь — что она не противоречит ДРУГОЙ. Ссылку выдаёт одна
// сторона звезды, а принимает другая, и половины написаны на разных языках: расхождение здесь не
// падает и не видно — ссылка «принялась», а туннель молчит, потому что маска оказалась другой или
// keepalive включился сам.
//
// Вектор ниже — не выдумка: это вывод steer/tests/xslinkmatch.c на той же конфигурации. Обе
// стороны держат один и тот же вектор в своём стенде, поэтому изменение формата в одной половине
// валит стенд в обеих, а не тихо расходится.
func TestКрестСРеализациейНаC(t *testing.T) {
	file := `[Interface]
PrivateKey = 6Gtidge6FqhO/0LhrAWpRiyYaKdLZF/gib/HePLC9GU=
Address    = 10.77.0.5/24
MTU        = 1400
DNS        = 10.77.0.1

[Peer]
PublicKey  = QYkH5bWOsEOCgIMldHPATSG7yvNyJ8st7o/HMelWKxs=
AllowedIPs = 0.0.0.0/0
Endpoint   = 198.51.100.9:8443
PersistentKeepalive = 0
`
	c, s, err := Parse([]byte(file), RoleSpoke)
	if err != nil {
		t.Fatal(err)
	}
	link, err := Link(c, s, "узел один")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("GO ПЕЧАТАЕТ: %s", link)
	// Ссылка, напечатанная половиной на C (вектор из steer/tests/xslinkmatch.c).
	const fromC = "xs://6Gtidge6FqhO_0LhrAWpRiyYaKdLZF_gib_HePLC9GU@198.51.100.9:8443" +
		"?pk=QYkH5bWOsEOCgIMldHPATSG7yvNyJ8st7o_HMelWKxs&ip=10.77.0.5/24&allowed=0.0.0.0/0" +
		"&mtu=1400&ka=0&dns=10.77.0.1" +
		"#%D1%83%D0%B7%D0%B5%D0%BB%20%D0%BE%D0%B4%D0%B8%D0%BD"
	if link != fromC {
		t.Errorf("печать разошлась:\n Go: %s\n  C: %s", link, fromC)
	}
	c2, s2, name, err := ParseLink(fromC, RoleSpoke)
	if err != nil {
		t.Fatalf("Go не принял ссылку от C: %v", err)
	}
	defer s2.Wipe()
	if name != "узел один" || c2.MTU != 1400 || len(c2.DNS) != 1 || c2.DNS[0] != "10.77.0.1" ||
		!c2.Peers[0].KeepaliveSet || c2.Peers[0].Keepalive != 0 {
		t.Errorf("Go разобрал ссылку от C не так: name=%q %+v", name, c2)
	}
}
