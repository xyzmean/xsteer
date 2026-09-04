package link

import "testing"

// Порог мёртвого пути и учёт НЕ НАШЕЙ тишины. Тот же набор случаев, что у стенда движка на C
// (steer/tests/xsconnmatch.c): решение здесь принимается одно и то же, и расхождение означало бы,
// что один и тот же пир на одном хабе живёт, а на другом переподнимается каждые секунды.
//
// Ни сокета, ни сети: время приходит в c.tick аргументом, а отправки на этих дорожках нет —
// отложенное подтверждение не срабатывает, пока unacked нулевой.
func ready(now int64) *Conn {
	return &Conn{state: StateEst, born: now, lastRX: now, lastTX: now, lastDataTX: now}
}

func TestTickDeadOnSteadySilence(t *testing.T) {
	t0 := int64(1000000)
	c := ready(t0)
	c.lastTX, c.lastDataTX = t0+1, t0+1 // отправили НАГРУЗКУ после того, как получили
	deadAt := int64(0)
	for u := t0; u <= t0+DeadMS+200; u += 20 {
		if err := c.tick(u); err != nil {
			deadAt = u - t0
			break
		}
	}
	if deadAt <= DeadMS || deadAt > DeadMS+20 {
		t.Fatalf("ровный ход: приговор ждали в (%d, %d], получили %d", DeadMS, DeadMS+20, deadAt)
	}
}

func TestTickStarvationIsNotDeath(t *testing.T) {
	t0 := int64(1000000)
	c := ready(t0)
	c.lastTX, c.lastDataTX = t0+1, t0+1
	for u := t0; u <= t0+DeadMS+2000; u += 2000 {
		if err := c.tick(u); err != nil {
			t.Fatalf("голодание по процессору принято за мёртвый путь на %d мс", u-t0)
		}
	}
}

// Главный случай: покой дольше порога, а потом отправка. Срок на ответ обязан быть полным — та
// самая ошибка, из-за которой живой туннель роутер↔VPS переподнимался каждые пятнадцать секунд.
func TestTickRestThenSendGetsFullTerm(t *testing.T) {
	t0 := int64(1000000)
	c := ready(t0)
	c.lastRX = t0 + 1 // получили последними: отправлять нечего, мы на покое
	u := t0
	for ; u <= t0+25000; u += 20 {
		if err := c.tick(u); err != nil {
			t.Fatalf("покой сам по себе убил соединение на %d мс", u-t0)
		}
	}
	c.lastTX, c.lastDataTX = u, u // появился пакет
	deadAt := int64(0)
	for v := u; v <= u+2*DeadMS; v += 20 {
		if err := c.tick(v); err != nil {
			deadAt = v - u
			break
		}
	}
	// Срок полный с точностью до тика: покой засчитывается по ВЫЗОВАМ tick, поэтому последние
	// двадцать миллисекунд покоя в запас не попадают.
	if deadAt < DeadMS || deadAt > DeadMS+20 {
		t.Fatalf("после покоя срок ждали в [%d, %d], получили %d", DeadMS, DeadMS+20, deadAt)
	}
}

// Голое подтверждение — не разговор. Сторона, которая приняла запись, подтвердила её и замолчала,
// ничего у пути не спрашивала: подтверждения не подтверждают ни здесь, ни в настоящем стеке.
// Именно этот случай уносил простаивающие сессии на хабе за восемь секунд, а пир видел только
// собственную тишину и переподнимал соединение каждые двадцать-сорок секунд.
func TestTickBareAckIsNotTalking(t *testing.T) {
	t0 := int64(1000000)
	c := ready(t0)
	c.lastRX = t0            // приняли запись
	c.lastTX = t0 + 5        // и подтвердили её голым ACK
	c.lastDataTX = t0 - 1000 // нагрузку отправляли давно, ещё до приёма
	for u := t0; u <= t0+10*DeadMS; u += 20 {
		if err := c.tick(u); err != nil {
			t.Fatalf("голое подтверждение принято за разговор: путь объявлен мёртвым на %d мс", u-t0)
		}
	}
}
