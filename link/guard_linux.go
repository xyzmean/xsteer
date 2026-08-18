//go:build linux

package link

import (
	"fmt"
	"os/exec"
	"strconv"
)

// Правило против RST СОБСТВЕННОГО ядра.
//
// Ядро видит входящие сегменты (сырой сокет получает копию, а не перехватывает их) и, не найдя
// своего сокета, отвечает RST — то есть рвёт нашу же сессию. Гасим ровно исходящий RST этого
// потока и только его.
//
// Три решения здесь куплены упавшими туннелями, и менять их без замера нельзя:
//
//   - ПРИОРИТЕТ raw, А НЕ filter. conntrack смотрит исходящий пакет на приоритете -200, то есть
//     раньше цепочки filter. Пока правило стояло там, RST ядра успевал перевести запись conntrack
//     в CLOSE и лишь потом отбрасывался — а дальше каждый наш сегмент был для conntrack
//     недействительным, и штатное правило «drop invalid» выбрасывало его. Симптом был из самых
//     злых: туннель то работает, то теряет большинство пакетов.
//   - `tcp window 0` ОТДЕЛЯЕТ RST ЯДРА ОТ НАСТОЯЩЕГО. Ядро шлёт RST на несуществующее соединение
//     всегда с нулевым окном, а мы объявляем 65535 — и настоящий RST нам НУЖЕН: им хаб сообщает,
//     что сессии больше нет (например, после перезапуска). Без различения клиент узнавал бы об
//     этом только по тишине, то есть через минуту.
//   - МАСКА `flags & rst == rst`, а не голое `flags rst`: ядро отвечает на SYN закрытого порта не
//     чистым RST, а RST+ACK, и запись без маски в части версий nft читается как сравнение поля
//     флагов целиком — тогда правило ловит RST на данные и пропускает ровно тот, который рвёт
//     рукопожатие.
//
// Таблица общая с обфускатором движка (`inet steer_obfs`, имя историческое), а цепочка своя: иначе
// выход одного процесса снимал бы правило другого.
type Guard struct{ chain string }

// GuardUp ставит правило. Ошибку возвращает, но НЕ считает смертельной: без nft туннель
// поднимется и, возможно, будет работать — на многих системах локальный RST не мешает, — а вот
// молча притворяться, что защита есть, нельзя.
func GuardUp(label, peerAddr string, port int) (*Guard, error) {
	if _, err := exec.LookPath("nft"); err != nil {
		return nil, fmt.Errorf("нет nft: правило против RST собственного ядра не встанет")
	}
	g := &Guard{chain: "x_" + safeLabel(label)}
	if err := nft("add", "table", "inet", "steer_obfs"); err != nil {
		return nil, err
	}
	// Снять хвост от прошлого падения: процесс мог уйти по SIGKILL, и тогда цепочка осталась, а
	// `add` поверх неё правило задвоил бы.
	_ = nft("delete", "chain", "inet", "steer_obfs", g.chain)
	if err := nft("add", "chain", "inet", "steer_obfs", g.chain,
		"{ type filter hook output priority raw; policy accept; }"); err != nil {
		return nil, err
	}
	if err := nft("add", "rule", "inet", "steer_obfs", g.chain,
		"ip", "daddr", peerAddr, "tcp", "dport", strconv.Itoa(port),
		"tcp", "flags", "&", "rst", "==", "rst",
		"tcp", "window", "0", "counter", "drop"); err != nil {
		return nil, err
	}
	return g, nil
}

// Down снимает цепочку целиком. Зовётся при штатном выходе; при SIGKILL остаётся хвост, который
// снимет следующий запуск — поэтому GuardUp и начинает с удаления.
func (g *Guard) Down() {
	if g == nil {
		return
	}
	_ = nft("delete", "chain", "inet", "steer_obfs", g.chain)
}

func nft(args ...string) error {
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %v: %v: %s", args, err, out)
	}
	return nil
}

// safeLabel: в имени цепочки только буквы, цифры и подчёркивание. Имя приходит из настроек, то
// есть от человека, и попадает в командную строку nft — проверка здесь не гигиена, а граница.
func safeLabel(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s) && i < 40; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "x"
	}
	return string(out)
}
