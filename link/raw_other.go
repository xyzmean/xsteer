//go:build !linux

package link

import (
	"fmt"
	"runtime"
)

// OpenRaw на прочих системах пока не реализован, и отказ называет ПРИЧИНУ и то, чем это лечится.
// Молчаливая заглушка была бы хуже: она выглядит как реализованная возможность.
//
// macOS. Сырой сокет умеет ОТПРАВЛЯТЬ TCP (с IP_HDRINCL), но не умеет его ПРИНИМАТЬ: BSD не
// доставляет TCP на сырые сокеты вовсе. Значит приём придётся делать через /dev/bpf, а это своя
// работа с фильтром и своим форматом заголовков.
//
// Windows. Отправка TCP через сырой сокет запрещена системой начиная с XP SP2 — не настройкой, а
// принципиально. Путь один: перехватчик (WinDivert или Npcap), и это отдельная зависимость с
// собственным драйвером, которую надо и подписать, и установить.
//
// Пока этого нет, честнее отказать прямо здесь, чем поднять туннель, который не понесёт ни одного
// пакета.
func OpenRaw(daddr [4]byte, sport, dport uint16) (Raw, error) {
	switch runtime.GOOS {
	case "darwin":
		return nil, fmt.Errorf("на macOS приём поддельного TCP требует /dev/bpf — ещё не сделано")
	case "windows":
		return nil, fmt.Errorf("на Windows отправка сырого TCP запрещена системой; нужен " +
			"перехватчик WinDivert или Npcap — ещё не сделано")
	}
	return nil, fmt.Errorf("сырой сокет на %s ещё не сделан", runtime.GOOS)
}

// EgressMTU без платформенной части возвращает ноль: тогда предел считается по умолчанию, а
// сузить его до настоящего всё равно обязаны пробы пути.
func EgressMTU(local [4]byte) (int, string) { return 0, "" }

// Guard — на системах без nftables правила против RST собственного ядра нет. Это не значит, что
// проблемы нет: она решается там же, где решается перехват пакетов, и вместе с ним.
type Guard struct{}

func GuardUp(label, peerAddr string, port int) (*Guard, error) {
	return nil, fmt.Errorf("правило против RST собственного ядра на %s ещё не сделано", runtime.GOOS)
}

func (g *Guard) Down() {}

// Слушающая половина на прочих системах не нужна и не сделана: хаб живёт на сервере с Linux.
//
// Заглушки существуют ровно для того, чтобы пакет собирался под Windows и macOS — там нужен
// КЛИЕНТ, и он в режиме потока сырых сокетов не требует вовсе. Отказ называет это прямо, а не
// притворяется, будто хаб можно поднять и он просто не работает.
func OpenRawListen(port uint16, mask, id uint16) (Raw, error) {
	return nil, fmt.Errorf("хаб на %s не поддерживается: слушающая половина живёт на сервере с Linux",
		runtime.GOOS)
}

func OpenRawSend(daddr, saddr [4]byte) (Raw, error) {
	return nil, fmt.Errorf("сырой сокет на %s не сделан: клиент здесь работает режимом потока (--stream)",
		runtime.GOOS)
}

func GuardUpServer(port int) (*Guard, error) {
	return nil, fmt.Errorf("правило против RST на %s не сделано", runtime.GOOS)
}
