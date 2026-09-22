//go:build linux

package tun

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Пара сокетов вместо настоящего устройства TUN.
//
// Настоящее в тесте не открыть: /dev/net/tun требует прав, которых у сборочной машины нет, и
// проверка молча пропускалась бы ровно там, где она нужна. А проверяем мы здесь обёртку, а не
// ядро: что дескриптор переведён в неблокирующий режим, что пустота даёт ErrAgain, что MTU
// принимается, и что закрытие однократно. Для всего этого пара сокетов ведёт себя так же.
func pair(t *testing.T) (ours, theirs int) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("пропущено: socketpair недоступен (%v)", err)
	}
	return fds[0], fds[1]
}

func TestFromFDОтвергаетНеДескриптор(t *testing.T) {
	if _, err := FromFD(-1, "xs0", 1400); !errors.Is(err, ErrNoDevice) {
		t.Fatalf("минус первый дал %v, ждали ErrNoDevice", err)
	}
}

// Пустое устройство обязано отвечать ErrAgain, а не ждать пакета: на блокирующем чтении путь
// данных перестал бы собирать пачки и замер бы на первом затишье.
func TestFromFDПустотаДаётErrAgain(t *testing.T) {
	ours, theirs := pair(t)
	defer unix.Close(theirs)
	d, err := FromFD(ours, "xs0", 1400)
	if err != nil {
		t.Fatalf("FromFD: %v", err)
	}
	defer d.Close()
	buf := make([]byte, 1500)
	if n, err := d.Read(buf); n != 0 || !errors.Is(err, ErrAgain) {
		t.Fatalf("пусто дало (%d, %v), ждали (0, ErrAgain)", n, err)
	}
}

func TestFromFDЧитаетИПишет(t *testing.T) {
	ours, theirs := pair(t)
	defer unix.Close(theirs)
	d, err := FromFD(ours, "xs0", 1400)
	if err != nil {
		t.Fatalf("FromFD: %v", err)
	}
	defer d.Close()

	// То, что пришло от системы, читается целиком.
	want := []byte{0x45, 0, 0, 40, 1, 2, 3, 4}
	if _, err := unix.Write(theirs, want); err != nil {
		t.Fatalf("запись в другой конец: %v", err)
	}
	ok, err := d.WaitRead(time.Second)
	if err != nil || !ok {
		t.Fatalf("WaitRead дал (%v, %v)", ok, err)
	}
	buf := make([]byte, 1500)
	n, err := d.Read(buf)
	if err != nil || n != len(want) || string(buf[:n]) != string(want) {
		t.Fatalf("прочитано (%d, %v): %x", n, err, buf[:n])
	}

	// То, что мы записали, доходит до системы.
	out := []byte{0x60, 1, 2, 3}
	if n, err := d.Write(out); err != nil || n != len(out) {
		t.Fatalf("запись дала (%d, %v)", n, err)
	}
	got := make([]byte, 16)
	rn, err := unix.Read(theirs, got)
	if err != nil || string(got[:rn]) != string(out) {
		t.Fatalf("другой конец получил %x (%v)", got[:rn], err)
	}
}

// Ожидание по истечении срока возвращает «нет» без ошибки: ошибку вызывающий считает
// смертельной и уходит из соединения.
func TestFromFDОжиданиеНеОшибка(t *testing.T) {
	ours, theirs := pair(t)
	defer unix.Close(theirs)
	d, _ := FromFD(ours, "xs0", 1400)
	defer d.Close()
	start := time.Now()
	ok, err := d.WaitRead(50 * time.Millisecond)
	if err != nil {
		t.Fatalf("таймаут дал отказ: %v", err)
	}
	if ok {
		t.Fatal("на пустом устройстве сказано, что есть что читать")
	}
	if el := time.Since(start); el < 40*time.Millisecond {
		t.Fatalf("вернулся через %v, то есть не ждал", el)
	}
}

// MTU принимается молча. Отказ означал бы, что клиент не обновит свой рабочий MTU после
// согласования пути и навсегда останется на стартовом, — то есть сделал бы хуже, чем согласие.
func TestFromFDПринимаетMTU(t *testing.T) {
	ours, theirs := pair(t)
	defer unix.Close(theirs)
	d, _ := FromFD(ours, "xs0", 1400)
	defer d.Close()
	if err := d.SetMTU(1380); err != nil {
		t.Fatalf("SetMTU дал отказ: %v", err)
	}
	if got := d.(interface{ MTU() int }).MTU(); got != 1380 {
		t.Fatalf("MTU %d, ждали 1380", got)
	}
}

// Flush без разгрузки ничего не делает и не отказывает: писать уже нечего, каждый пакет ушёл
// своим вызовом.
func TestFromFDFlushБезразличен(t *testing.T) {
	ours, theirs := pair(t)
	defer unix.Close(theirs)
	d, _ := FromFD(ours, "xs0", 1400)
	defer d.Close()
	if err := d.Flush(); err != nil {
		t.Fatalf("Flush дал отказ: %v", err)
	}
}

// ГЛАВНАЯ проверка этого файла: закрытие однократно.
//
// Закрыть норовят двое — клиент, когда уходят его горутины, и тот, кто туннель останавливал.
// Между двумя вызовами ядро успевает выдать этот же номер кому угодно, и второй Close закрыл бы
// ЕГО. Здесь это проверяется дословно: после первого закрытия занимается новый дескриптор, и
// второй Close не должен его тронуть.
func TestFromFDЗакрытиеОднократно(t *testing.T) {
	ours, theirs := pair(t)
	defer unix.Close(theirs)
	d, _ := FromFD(ours, "xs0", 1400)

	if err := d.Close(); err != nil {
		t.Fatalf("первое закрытие: %v", err)
	}
	// Новый дескриптор с большой вероятностью получит освободившийся номер.
	victim, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("пропущено: сокет не открылся (%v)", err)
	}
	defer unix.Close(victim)

	if err := d.Close(); err != nil {
		t.Fatalf("второе закрытие вернуло ошибку вместо тишины: %v", err)
	}
	// Если второе закрытие закрыло чужой номер, эта проверка провалится.
	if _, err := unix.Write(victim, []byte("живой")); err == unix.EBADF {
		t.Fatal("второе закрытие закрыло ЧУЖОЙ дескриптор")
	}
}
