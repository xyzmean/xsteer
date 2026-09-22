package xsteer

import (
	"encoding/json"
	"strings"
	"testing"
)

const goodConf = `[Interface]
PrivateKey = 8BT4UvilnYyF0j+Gt5uy/oMUqH9NYOg3TrKQ/NS59lw=
Address = 10.77.0.2/24
MTU = 1400
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = pvlciAMuJnL06ZXI5X0LgBaeA5Zty5OsqNaE7ikzaUg=
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.7:443
`

func TestConfigureAndSettings(t *testing.T) {
	tn := NewTunnel()
	if err := tn.Configure(goodConf); err != nil {
		t.Fatalf("настройка не разобралась: %v", err)
	}
	if got := tn.Address(); got != "10.77.0.2" {
		t.Fatalf("адрес %q", got)
	}
	if got := tn.Netmask(); got != "255.255.255.0" {
		t.Fatalf("маска %q", got)
	}
	if got := tn.IncludedRoutes(); got != "0.0.0.0/0" {
		t.Fatalf("маршруты %q", got)
	}
	if got := tn.DNSServers(); got != "1.1.1.1,8.8.8.8" {
		t.Fatalf("резолверы %q", got)
	}
	if got := tn.HubAddress(); got != "203.0.113.7" {
		t.Fatalf("хаб %q", got)
	}
	if got := tn.HubPort(); got != 443 {
		t.Fatalf("порт хаба %d", got)
	}
	if got := tn.MTU(); got != 1400 {
		t.Fatalf("MTU %d, ждали 1400 из настройки", got)
	}
}

// MTU, заданный больше того, что туннель готов нести, обязан быть зажат: путь данных читает
// пакеты окном MaxMTU и признака усечения не имеет, так что более крупный пакет пропал бы целиком.
func TestMTUIsClampedToMax(t *testing.T) {
	tn := NewTunnel()
	conf := strings.Replace(goodConf, "MTU = 1400", "MTU = 1500", 1)
	if err := tn.Configure(conf); err != nil {
		t.Fatalf("настройка не разобралась: %v", err)
	}
	if got := tn.MTU(); got != MaxMTU {
		t.Fatalf("MTU %d, ждали зажатый до %d", got, MaxMTU)
	}
}

// Без MTU в настройке берётся потолок, а не ноль: ноль система не примет.
func TestMTUDefaultsToMax(t *testing.T) {
	tn := NewTunnel()
	conf := strings.Replace(goodConf, "MTU = 1400\n", "", 1)
	if err := tn.Configure(conf); err != nil {
		t.Fatalf("настройка не разобралась: %v", err)
	}
	if got := tn.MTU(); got != MaxMTU {
		t.Fatalf("MTU %d, ждали %d", got, MaxMTU)
	}
}

// Отказ разбора обязан доходить до человека тем же текстом, что в консольной половине, — иначе
// одна и та же настройка объясняется двумя разными способами.
func TestConfigureReportsParseError(t *testing.T) {
	tn := NewTunnel()
	err := tn.Configure("[Interface]\nAddress = 10.0.0.2/24\n")
	if err == nil {
		t.Fatal("настройка без приватного ключа принята")
	}
	if !strings.Contains(err.Error(), "PrivateKey") {
		t.Fatalf("отказ не называет, чего не хватает: %v", err)
	}
}

func TestConfigureRejectsEmpty(t *testing.T) {
	if err := NewTunnel().Configure("   \n  "); err == nil {
		t.Fatal("пустая настройка принята")
	}
}

// Ссылка xs:// разбирается тем же путём и даёт то же самое.
func TestConfigureLink(t *testing.T) {
	tn := NewTunnel()
	link := "xs://8BT4UvilnYyF0j-Gt5uy_oMUqH9NYOg3TrKQ_NS59lw@203.0.113.7:443" +
		"?pk=pvlciAMuJnL06ZXI5X0LgBaeA5Zty5OsqNaE7ikzaUg&ip=10.77.0.2/24&allowed=0.0.0.0/0#дом"
	if err := tn.Configure(link); err != nil {
		t.Fatalf("ссылка не разобралась: %v", err)
	}
	if got := tn.Address(); got != "10.77.0.2" {
		t.Fatalf("адрес из ссылки %q", got)
	}
	if got := tn.Name(); got != "дом" {
		t.Fatalf("имя из ссылки %q", got)
	}
}

// Литерал адреса остаётся литералом: обычный случай правка строки задевать не должна вовсе, и
// повторный вызов ничего не меняет.
func TestResolveLeavesLiteralAlone(t *testing.T) {
	out, err := resolveEndpoints(goodConf)
	if err != nil {
		t.Fatalf("отказ на литерале: %v", err)
	}
	if out != goodConf {
		t.Fatalf("литерал переписан:\n%s", out)
	}
	again, err := resolveEndpoints(out)
	if err != nil || again != out {
		t.Fatal("повторный вызов изменил текст")
	}
}

func TestResolveLinkLeavesLiteralAlone(t *testing.T) {
	link := "xs://KEY@203.0.113.7:443?pk=X&ip=10.0.0.2/24#дом"
	out, err := resolveInLink(link)
	if err != nil || out != link {
		t.Fatalf("ссылка с литералом изменилась: %q, %v", out, err)
	}
}

// Адрес IPv6 отвергается прямо, а не превращается в невнятный отказ формата: движок несёт только
// IPv4, и сказать об этом надо тем словом, которое есть у человека.
func TestResolveRejectsIPv6Endpoint(t *testing.T) {
	conf := strings.Replace(goodConf, "Endpoint = 203.0.113.7:443", "Endpoint = [2001:db8::1]:443", 1)
	_, err := resolveEndpoints(conf)
	if err == nil {
		t.Fatal("адрес IPv6 принят")
	}
	if !strings.Contains(err.Error(), "IPv6") {
		t.Fatalf("отказ не называет причину: %v", err)
	}
}

// Мусор в Endpoint не должен падать здесь: о нём обязан сказать разбор формата, с номером строки.
func TestResolvePassesGarbageOn(t *testing.T) {
	conf := strings.Replace(goodConf, "Endpoint = 203.0.113.7:443", "Endpoint = ерунда", 1)
	out, err := resolveEndpoints(conf)
	if err != nil {
		t.Fatalf("мусор остановился здесь вместо разбора: %v", err)
	}
	if !strings.Contains(out, "ерунда") {
		t.Fatal("мусор пропал по дороге")
	}
	if err := NewTunnel().Configure(conf); err == nil {
		t.Fatal("мусор в Endpoint принят разбором")
	}
}

func TestStateJSONBeforeStart(t *testing.T) {
	tn := NewTunnel()
	var m map[string]any
	if err := json.Unmarshal([]byte(tn.StateJSON()), &m); err != nil {
		t.Fatalf("снимок не JSON: %v", err)
	}
	if m["up"] != false {
		t.Fatalf("неподнятый туннель сказал up=%v", m["up"])
	}
}

func TestStartWithoutConfigure(t *testing.T) {
	if err := NewTunnel().Start(&sinkRec{}, "utun"); err == nil {
		t.Fatal("подъём без настройки разрешён")
	}
}

func TestStartWithoutSink(t *testing.T) {
	tn := NewTunnel()
	if err := tn.Configure(goodConf); err != nil {
		t.Fatal(err)
	}
	if err := tn.Start(nil, "utun"); err == nil {
		t.Fatal("подъём без получателя пакетов разрешён")
	}
}

// Stop на неподнятом туннеле обязан быть безобидным: расширение зовёт его и на пути отказа.
func TestStopIdempotent(t *testing.T) {
	tn := NewTunnel()
	tn.Stop()
	tn.Stop()
}

// Ключ — 32 байта в base64, ровно 44 символа, и публичный из него выводится.
func TestKeys(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("ключ не создался: %v", err)
	}
	if len(priv) != 44 {
		t.Fatalf("длина ключа %d, ждали 44", len(priv))
	}
	pub, err := PublicKeyOf(priv)
	if err != nil {
		t.Fatalf("публичный не вывелся: %v", err)
	}
	if len(pub) != 44 {
		t.Fatalf("длина публичного %d", len(pub))
	}
	if pub == priv {
		t.Fatal("публичный совпал с приватным")
	}
	// Дважды из одного приватного — один и тот же публичный.
	again, _ := PublicKeyOf(priv)
	if again != pub {
		t.Fatal("публичный ключ не воспроизводится")
	}
	if _, err := PublicKeyOf("не ключ"); err == nil {
		t.Fatal("мусор принят за приватный ключ")
	}
}

// Два вызова подряд дают разные ключи. Проверка дешёвая, а её отсутствие однажды скрыло бы
// подмену генератора заглушкой.
func TestGenerateKeyDiffers(t *testing.T) {
	a, _ := GenerateKey()
	b, _ := GenerateKey()
	if a == b {
		t.Fatal("два ключа подряд совпали")
	}
}

// Пара ключей, вынесенная типом: именно её видит Swift.
func TestKeysType(t *testing.T) {
	k := NewKeys()
	if err := k.Generate(); err != nil {
		t.Fatalf("пара не создалась: %v", err)
	}
	if len(k.PrivateKey()) != 44 || len(k.PublicKey()) != 44 {
		t.Fatalf("длины %d и %d", len(k.PrivateKey()), len(k.PublicKey()))
	}
	// Вывод из готового приватного даёт тот же публичный.
	k2 := NewKeys()
	if err := k2.DeriveFrom(k.PrivateKey()); err != nil {
		t.Fatalf("вывод не удался: %v", err)
	}
	if k2.PublicKey() != k.PublicKey() {
		t.Fatal("публичный ключ не воспроизвёлся")
	}
	if err := NewKeys().DeriveFrom("не ключ"); err == nil {
		t.Fatal("мусор принят за приватный ключ")
	}
	// Пустая пара — пустые строки, а не мусор: интерфейс покажет её до нажатия.
	if NewKeys().PrivateKey() != "" || NewKeys().PublicKey() != "" {
		t.Fatal("пустая пара не пуста")
	}
}
