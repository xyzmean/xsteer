//go:build !windows

package main

// На прочих системах закрытие терминала приходит как SIGHUP, а завершение — как SIGTERM, и оба
// ловит os/signal вместе с Ctrl-C. Отдельный обработчик нужен только Windows, где крестик на
// окне не сигнал вовсе (см. console_windows.go).
func installConsoleHandler(stop func(), done <-chan struct{}) { _, _ = stop, done }
