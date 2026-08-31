//go:build linux

package tun

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

// Очередь устройства обязана быть ТОЙ, о которой просили, — и проверяется это прочитанным
// обратно значением, а не тем, что команда запустилась.
//
// ЗАЧЕМ. txqueuelen — длина очереди пакетов, которые ядро держит для читателя устройства (см.
// комментарий к TxQueueLen). По умолчанию она 500, и всё, что в неё не влезло, ядро отбрасывает
// молча — снаружи это видно только как «на пиках часть адресов подтормаживает». Движок на C
// поднимает её до 4096 третьей командой подъёма, а реализация на Go не поднимала вовсе: подъём
// делали SetAddr и SetMTU, очередь оставалась ядерной и у клиента, и у хаба (I-115).
//
// Проверять надо именно ПРИМЕНЁННОЕ значение. Команда `ip link set ... txqueuelen` возвращает
// ноль и там, где настройку не приняли молча, поэтому «отработала без ошибки» ничего не
// доказывает; единственный источник правды — /sys/class/net/<dev>/tx_queue_len.
//
// Нужно НАСТОЯЩЕЕ устройство. Без /dev/net/tun и CAP_NET_ADMIN тест пропускается ВСЛУХ, как и
// TestOpenRefusesTruncatedName рядом: молчаливый пропуск проверки очереди выглядел бы точно так
// же, как её прохождение.
const devQueue = "xs-goqlen"

func readQueueLen(t *testing.T, name string) int {
	t.Helper()
	b, err := os.ReadFile("/sys/class/net/" + name + "/tx_queue_len")
	if err != nil {
		t.Fatalf("не прочитать tx_queue_len устройства %s: %v", name, err)
	}
	v, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("tx_queue_len устройства %s не число: %q", name, b)
	}
	return v
}

func TestSetTxQueueLenApplied(t *testing.T) {
	d, err := openOne(devQueue, false, false)
	if err != nil {
		t.Skipf("пропущено: TUNSETIFF недоступен (%v) — нужны /dev/net/tun и CAP_NET_ADMIN", err)
	}
	defer d.Close()
	name := d.Name()

	// Свежесозданное устройство приходит с ядерной очередью. Не утверждение про число 500 (оно
	// зависит от системы), а фиксация того, что запас НЕ берётся сам: без вызова ниже клиент и
	// хаб работали ровно на этом значении.
	before := readQueueLen(t, name)
	if before == TxQueueLen {
		t.Skipf("пропущено: у нового устройства уже %d — проверка бессмысленна, "+
			"настройку системы не отличить от нашей", before)
	}

	if err := SetTxQueueLen(name, TxQueueLen); err != nil {
		t.Fatalf("txqueuelen %d не встал: %v", TxQueueLen, err)
	}
	if got := readQueueLen(t, name); got != TxQueueLen {
		t.Errorf("очередь устройства: применено %d, просили %d (было %d)", got, TxQueueLen, before)
	}
}

// Отказ обязан быть отказом, а не тишиной: у клиента и хаба на нём стоит осведомляющая строка, и
// если бы SetTxQueueLen возвращала nil на несуществующем устройстве, эта ветка была бы мёртвой —
// то есть «очередь осталась ядерной» никогда бы не напечаталось.
func TestSetTxQueueLenNamesFailure(t *testing.T) {
	err := SetTxQueueLen("xs-nosuchdev0", TxQueueLen)
	if err == nil {
		t.Fatal("txqueuelen на несуществующем устройстве прошёл без ошибки")
	}
	if !strings.Contains(err.Error(), "txqueuelen") {
		t.Errorf("в тексте ошибки нет команды, по которой её узнать: %v", err)
	}
}
