package conf

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Load открывает файл, проверяет ПРАВА, читает и разбирает. Только эта функция обращается к
// операционной системе — поэтому её и не проверяет тест в памяти.
func Load(path string, role Role) (*Conf, *Secrets, error) {
	// Lstat, а не Stat: символьная ссылка отвергается до открытия. Нацеленная на файл с
	// чужими секретами, она положила бы его содержимое в текст ошибки разбора, то есть в
	// журнал и в вывод диагностики.
	st, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("%s: символьная ссылка — читать конфигурацию по ссылке "+
			"небезопасно: её цель может смениться между проверкой и чтением", path)
	}
	if !st.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: не обычный файл", path)
	}
	if st.Size() > ConfMax {
		return nil, nil, fmt.Errorf("%s: больше %d КиБ", path, ConfMax/1024)
	}
	if err := checkPerm(path, st); err != nil {
		return nil, nil, err
	}
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return Parse(text, role)
}

// LoadAny принимает то, что дал человек: путь к файлу, ссылку xs:// или «-» (читать со
// стандартного ввода). Третье возвращаемое значение — имя из ссылки, пустое для файла.
//
// ЗАЧЕМ «-». Ссылка содержит приватный ключ, а аргументы команды видны в списке процессов всякому,
// кто есть на машине, и остаются в истории оболочки. На своём ноутбуке это неважно, на общем
// сервере — важно, и единственный честный ответ на это не предупреждение в справке, а работающий
// способ передать ссылку иначе. Со стандартного ввода принимается и ссылка, и целый файл
// конфигурации: различаются они первыми символами, а не ключом командной строки.
func LoadAny(what string, role Role) (*Conf, *Secrets, string, error) {
	if what == "-" {
		text, err := io.ReadAll(io.LimitReader(os.Stdin, ConfMax+1))
		if err != nil {
			return nil, nil, "", fmt.Errorf("чтение стандартного ввода: %w", err)
		}
		if len(text) > ConfMax {
			return nil, nil, "", fmt.Errorf("со стандартного ввода пришло больше %d КиБ", ConfMax/1024)
		}
		body := strings.TrimLeft(string(text), " \t\r\n")
		if IsLink(body) {
			return ParseLink(body, role)
		}
		c, s, err := Parse(text, role)
		return c, s, "", err
	}
	if IsLink(what) {
		return ParseLink(what, role)
	}
	c, s, err := Load(what, role)
	return c, s, "", err
}

// IsLink — это ссылка xs://, а не путь. Проверка по схеме, а не по наличию «://»: путь с таким
// содержимым завести можно, и спутать их значило бы читать файл как ссылку.
func IsLink(s string) bool {
	return len(s) > len(LinkScheme)+3 &&
		strings.EqualFold(s[:len(LinkScheme)+3], LinkScheme+"://")
}
