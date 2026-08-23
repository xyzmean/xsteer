package hub

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Закрывать то, чем ещё пользуются, нельзя — вот что здесь проверяется.
//
// ЗАЧЕМ. Прежде отмена контекста закрывала дескриптор устройства сразу, чтобы разбудить чтение. В
// этот же миг снимается обвязка туннеля (nft, ip — каждый через exec, а значит через трубы), и
// ядро выдаёт трубам наименьшие свободные номера, то есть только что освободившиеся. Пока воркер
// доживает свой виток, его запись уходит в буфер вывода чужого процесса, а чтение разбирает
// чужие байты как IP-пакет (I-109). Проверяется поэтому не «закрыли», а ПОРЯДОК: закрытие обязано
// стоять после последнего действия воркера.
//
// Полтораста миллисекунд у воркера — это тот самый таймаут WaitRead (200 мс у устройства, 50 мс у
// сырого сокета), из-за которого воркер и уходит не мгновенно.
func TestDrainThenCloseWaitsForWorkers(t *testing.T) {
	var (
		mu    sync.Mutex
		order []string
	)
	note := func(s string) { mu.Lock(); order = append(order, s); mu.Unlock() }

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		time.Sleep(150 * time.Millisecond)
		note("воркер ушёл")
	}()

	cancel()
	if !drainThenClose(ctx, &wg, 3*time.Second, func() { note("закрыли") }) {
		t.Fatal("отсрочка истекла, хотя воркер уходил за 150 мс из трёх секунд")
	}
	mu.Lock()
	defer mu.Unlock()
	want := []string{"воркер ушёл", "закрыли"}
	if len(order) != len(want) || order[0] != want[0] || order[1] != want[1] {
		t.Errorf("порядок завершения: %v, ожидался %v", order, want)
	}
}

// Если кто-то не проснулся, закрывать НЕЛЬЗЯ ВООБЩЕ: его номер дескриптора ещё в работе, и отдать
// его следующему открывшему — ровно та подмена объекта, от которой уходили. Дескрипторы в этом
// случае забирает выход процесса, а вместе с ними уходит и непостоянное устройство TUN.
func TestDrainThenCloseKeepsFdsWhenSomeoneHangs(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); <-release }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	closed := false
	start := time.Now()
	if drainThenClose(ctx, &wg, 200*time.Millisecond, func() { closed = true }) {
		t.Error("зависшего воркера сочли ушедшим")
	}
	if closed {
		t.Error("дескрипторы закрыты, пока воркер ещё в цикле")
	}
	if el := time.Since(start); el < 200*time.Millisecond {
		t.Errorf("отсрочка не выдержана: ушли через %v", el)
	}
}

// Без отмены ждать нечего и закрывать нечего до тех пор, пока воркеры сами не разойдутся: у
// клиента это бывает, когда все соединения отказали окончательно.
func TestDrainThenCloseWithoutCancel(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); time.Sleep(20 * time.Millisecond) }()
	closed := false
	if !drainThenClose(context.Background(), &wg, time.Second, func() { closed = true }) {
		t.Fatal("воркеры разошлись сами, а завершение сочло это отсрочкой")
	}
	if !closed {
		t.Error("воркеры ушли, а дескрипторы не закрыты")
	}
}
