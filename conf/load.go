package conf

import (
	"fmt"
	"os"
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
