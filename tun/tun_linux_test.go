//go:build linux

package tun

import (
	"errors"
	"os"
	"testing"
)

// Имя устройства обязано быть тем, о котором просили.
//
// ЗАЧЕМ. Ядро принимает имя в поле из 16 байт, а всё, что длиннее 15 значащих символов,
// обрезается ещё на нашей стороне (copy в req.name[:15]). Устройство создаётся — просто с
// ДРУГИМ именем. Здесь это до сих пор было безвредно, но не безобидно: openOne читал имя
// обратно и возвращал полученное, поэтому дальше всё работало с настоящим устройством, а
// человек видел в настройках одно имя, в системе — другое. На той же ошибке в реализации на C
// туннель поднимался на несуществующем имени (I-107): там имя обратно не читалось вовсе.
//
// Проверяется отказ, а не подстановка. Имя устройства знает не только клиент: на него заведены
// маршруты, правила и (на роутере) зона firewall, и всё это создано по имени из настроек.
//
// Нужно НАСТОЯЩЕЕ устройство: TUNSETIFF — единственное место, где ядро сообщает имя. Без
// /dev/net/tun и CAP_NET_ADMIN тест пропускается вслух, как и стенд tunnamematch в steer.
const (
	nameOK   = "xs-gonamechk15"   // 14 символов — влезает целиком
	nameLong = "xs-gonamechk-16x" // 16 символов — первое, что не влезает
)

func devExists(t *testing.T, name string) bool {
	t.Helper()
	_, err := os.Stat("/sys/class/net/" + name)
	return err == nil
}

func TestOpenRefusesTruncatedName(t *testing.T) {
	d, err := openOne(nameOK, false, false)
	if err != nil {
		t.Skipf("пропущено: TUNSETIFF недоступен (%v) — нужны /dev/net/tun и CAP_NET_ADMIN", err)
	}
	if got := d.Name(); got != nameOK {
		t.Errorf("короткое имя: получено %q, ожидалось %q", got, nameOK)
	}
	if !devExists(t, nameOK) {
		t.Errorf("устройство %s не создалось", nameOK)
	}
	d.Close()

	// Усечение даёт то же имя без последнего знака — то есть ДРУГОЕ устройство, чем просили.
	long := nameLong
	cut := long[:15]
	d2, err := openOne(long, false, false)
	if err == nil {
		d2.Close()
		t.Fatalf("имя из %d символов принято, а должно быть отвергнуто", len(long))
	}
	if !errors.Is(err, ErrNoDevice) {
		t.Errorf("отказ не помечен ErrNoDevice: %v", err)
	}
	if devExists(t, cut) {
		t.Errorf("после отказа осталось устройство %s", cut)
	}
	if devExists(t, long) {
		t.Errorf("устройство с невозможным именем %s существует", long)
	}
}
