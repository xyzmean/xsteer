//go:build windows

package main

import (
	"time"

	"golang.org/x/sys/windows"
)

// Закрытие окна консоли на Windows — это НЕ сигнал, и Go его не ловит.
//
// os/signal на этой системе переводит в сигналы только Ctrl-C и Ctrl-Break. Крестик на окне,
// выход из системы и её выключение приходят как CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT и
// CTRL_SHUTDOWN_EVENT, и по умолчанию процесс просто исчезает — без единого defer. Для обычной
// программы это мелочь, для нашей — нет: за нами остаются маршрут по умолчанию, уведённый в
// мёртвый туннель, обход /32 на физическом интерфейсе и переписанные серверы имён. То есть
// человек, закрывший окно крестиком, получал машину без интернета и без всякого указания, что
// с ней случилось.
//
// Проверено на стенде: обход 109.120.137.190/32 пережил принудительное завершение процесса и
// остался в таблице маршрутов.
//
// Времени у обработчика немного: на CTRL_CLOSE_EVENT система даёт около пяти секунд, потом
// снимает процесс независимо от того, вернулись мы или нет. Поэтому ждём завершения уборки не
// дольше четырёх и уходим в любом случае — недоснятый маршрут лучше, чем зависшее окно, которое
// человек добьёт из диспетчера задач, и тогда не снимется вообще ничего.
const consoleGrace = 4 * time.Second

// SetConsoleCtrlHandler зовётся напрямую из kernel32: обёртки для неё в x/sys/windows нет, а
// константы событий там уже есть — берём их оттуда, чтобы не заводить своих чисел.
var procSetConsoleCtrlHandler = windows.NewLazySystemDLL("kernel32.dll").NewProc("SetConsoleCtrlHandler")

// installConsoleHandler просит систему звать нас перед закрытием. stop снимает туннель, done
// закрывается, когда уборка прошла.
func installConsoleHandler(stop func(), done <-chan struct{}) {
	handler := windows.NewCallback(func(ctrlType uint32) uintptr {
		switch ctrlType {
		case windows.CTRL_C_EVENT, windows.CTRL_BREAK_EVENT:
			// Эти два и так придут через os/signal — там уборка уже заведена. Отдаём их дальше,
			// чтобы не снимать туннель дважды.
			return 0
		case windows.CTRL_CLOSE_EVENT, windows.CTRL_LOGOFF_EVENT, windows.CTRL_SHUTDOWN_EVENT:
			stop()
			select {
			case <-done:
			case <-time.After(consoleGrace):
			}
			return 1 // обработано
		}
		return 0
	})
	// Ошибку сознательно не поднимаем наверх: не установившийся обработчик означает лишь то, что
	// закрытие окна останется неубранным, — а это ровно то поведение, которое было до него.
	// Ронять из-за этого рабочий туннель было бы хуже.
	_, _, _ = procSetConsoleCtrlHandler.Call(handler, 1)
}
