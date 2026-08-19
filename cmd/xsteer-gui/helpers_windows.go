//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/lxn/walk"
	dcl "github.com/lxn/walk/declarative"
	"github.com/xyzmean/xsteer/conf"
	"golang.org/x/crypto/curve25519"
)

func readState(path string) (*state, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st state
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func readText(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// confView — конфигурация, разобранная РОВНО для показа. Отдельно от conf.Parse нарочно: тот
// строгий и на недописанном файле отказывает целиком, а окну надо показать и половину — человек
// как раз и открывает правку, чтобы дописать остальное.
type confView struct {
	SelfPub  string // выведен из приватного ключа: в файле его нет, а видеть его нужно
	Address  string
	DNS      string
	MTU      string
	PeerPub  string
	Allowed  string
	Endpoint string
}

func parseConf(text string) confView {
	var c confView
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				c.SelfPub = pubFromPriv(val)
			case "address":
				c.Address = val
			case "dns":
				c.DNS = val
			case "mtu":
				c.MTU = val
			}
		case "peer":
			switch key {
			case "publickey":
				c.PeerPub = val
			case "allowedips":
				// Пробел после запятой: длинный список тогда переносится по элементам, а не
				// рвётся посередине адреса.
				c.Allowed = strings.Join(splitList(val), ", ")
			case "endpoint":
				c.Endpoint = val
			}
		}
	}
	return c
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// pubFromPriv выводит публичный ключ из приватного. Считается здесь, а не запуском `xsteer pubkey`:
// то же умножение на образующую, но без процесса на каждую перерисовку.
func pubFromPriv(b64 string) string {
	priv, err := conf.KeyDecode(b64)
	if err != nil {
		return ""
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return ""
	}
	var out [32]byte
	copy(out[:], pub)
	return conf.KeyEncode(out)
}

func dash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

// dashDefault — для полей, пустота которых значит не «неизвестно», а «решает движок».
func dashDefault(s, whenEmpty string) string {
	if strings.TrimSpace(s) == "" {
		return whenEmpty
	}
	return s
}

// since — человеческий вид возраста соединения.
//
// Сырые секунды показывать нельзя: xsteer НЕ ПЕРЕКЛЮЧАЕТ КЛЮЧИ по времени (в отличие от WireGuard,
// где рукопожатие обновляется каждые две минуты и число всегда маленькое). Здесь оно случается один
// раз при подъёме соединения, поэтому значение растёт неограниченно, и «2514 с назад» на живом
// туннеле читается как «связи давно нет», хотя всё в порядке. Крупные единицы возвращают числу
// смысл: это просто время работы соединения.
func since(sec int64) string {
	switch {
	case sec < 0:
		return "—"
	case sec < 5:
		return "только что"
	case sec < 60:
		return fmt.Sprintf("%d с назад", sec)
	case sec < 3600:
		return fmt.Sprintf("%d мин назад", sec/60)
	case sec < 24*3600:
		if m := (sec % 3600) / 60; m != 0 {
			return fmt.Sprintf("%d ч %d мин назад", sec/3600, m)
		}
		return fmt.Sprintf("%d ч назад", sec/3600)
	default:
		return fmt.Sprintf("%d дн %d ч назад", sec/(24*3600), (sec%(24*3600))/3600)
	}
}

var nameOK = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

// promptName — ввод имени нового туннеля. Имя станет именем файла, поэтому набор символов
// ограничен, и проверяется он сразу, а не при записи.
func promptName(owner walk.Form) (string, bool) {
	var dlg *walk.Dialog
	var edit *walk.LineEdit
	var okBtn, cancelBtn *walk.PushButton
	res := ""

	if err := (dcl.Dialog{
		AssignTo:      &dlg,
		Title:         "Имя туннеля",
		DefaultButton: &okBtn,
		CancelButton:  &cancelBtn,
		MinSize:       dcl.Size{Width: 360, Height: 130},
		Layout:        dcl.VBox{},
		Children: []dcl.Widget{
			dcl.Label{Text: "Буквы, цифры, дефис, подчёркивание и точка; до 32 символов."},
			dcl.LineEdit{AssignTo: &edit},
			dcl.Composite{
				Layout: dcl.HBox{MarginsZero: true},
				Children: []dcl.Widget{
					dcl.HSpacer{},
					dcl.PushButton{
						AssignTo: &okBtn,
						Text:     "ОК",
						MinSize:  dcl.Size{Width: 100},
						OnClicked: func() {
							v := strings.TrimSpace(edit.Text())
							if !nameOK.MatchString(v) {
								walk.MsgBox(dlg, "xsteer", "недопустимое имя", walk.MsgBoxIconWarning)
								return
							}
							res = v
							dlg.Accept()
						},
					},
					dcl.PushButton{AssignTo: &cancelBtn, Text: "Отмена", MinSize: dcl.Size{Width: 100},
						OnClicked: func() { dlg.Cancel() }},
				},
			},
		},
	}).Create(owner); err != nil {
		return "", false
	}
	if dlg.Run() == walk.DlgCmdOK {
		return res, true
	}
	return "", false
}

// editTunnel — окно правки: имя и текст конфигурации, как в AmneziaWG. Возвращает текст, имя и
// признак «сохранить». Ошибку разбора показывает сразу и НЕ закрывает окно: закрыть по «Сохранить»
// заведомо нерабочий файл значит отложить отказ до подключения, где он читается хуже.
func editTunnel(owner walk.Form, name, text string) (string, string, bool) {
	var dlg *walk.Dialog
	var nameEdit *walk.LineEdit
	var body *walk.TextEdit
	var pub *walk.Label
	var saveBtn, cancelBtn *walk.PushButton
	resText, resName, ok := "", "", false

	refreshPub := func() {
		if pub == nil || body == nil {
			return
		}
		c := parseConf(strings.ReplaceAll(body.Text(), "\r\n", "\n"))
		pub.SetText(dash(c.SelfPub))
	}

	if err := (dcl.Dialog{
		AssignTo:      &dlg,
		Title:         "Редактировать туннель",
		DefaultButton: &saveBtn,
		CancelButton:  &cancelBtn,
		MinSize:       dcl.Size{Width: 620, Height: 520},
		Layout:        dcl.VBox{},
		Children: []dcl.Widget{
			dcl.Composite{
				Layout: dcl.Grid{Columns: 2, MarginsZero: true, Spacing: 6},
				Children: []dcl.Widget{
					dcl.Label{Text: "Имя:", TextAlignment: dcl.AlignFar, MinSize: dcl.Size{Width: 120}},
					dcl.LineEdit{AssignTo: &nameEdit, Text: name},
					dcl.Label{Text: "Публичный ключ:", TextAlignment: dcl.AlignFar},
					dcl.Label{AssignTo: &pub, Text: "—"},
				},
			},
			dcl.TextEdit{
				AssignTo:      &body,
				Text:          strings.ReplaceAll(text, "\n", "\r\n"),
				VScroll:       true,
				HScroll:       true,
				StretchFactor: 1,
				Font:          dcl.Font{Family: "Consolas", PointSize: 10},
				OnTextChanged: func() { refreshPub() },
			},
			dcl.Composite{
				Layout: dcl.HBox{MarginsZero: true},
				Children: []dcl.Widget{
					dcl.HSpacer{},
					dcl.PushButton{
						AssignTo: &saveBtn,
						Text:     "Сохранить",
						MinSize:  dcl.Size{Width: 110},
						OnClicked: func() {
							t := strings.ReplaceAll(body.Text(), "\r\n", "\n")
							// Проверяем СТРОГИМ разбором движка — тем же, что применит клиент.
							if _, _, err := conf.Parse([]byte(t), conf.RoleSpoke); err != nil {
								if walk.MsgBox(dlg, "xsteer",
									"Конфигурация не проходит проверку:\n\n"+err.Error()+
										"\n\nСохранить всё равно?",
									walk.MsgBoxYesNo|walk.MsgBoxIconWarning) != walk.DlgCmdYes {
									return
								}
							}
							n := strings.TrimSpace(nameEdit.Text())
							if n != "" && !nameOK.MatchString(n) {
								walk.MsgBox(dlg, "xsteer", "недопустимое имя", walk.MsgBoxIconWarning)
								return
							}
							resText, resName, ok = t, n, true
							dlg.Accept()
						},
					},
					dcl.PushButton{AssignTo: &cancelBtn, Text: "Отмена", MinSize: dcl.Size{Width: 110},
						OnClicked: func() { dlg.Cancel() }},
				},
			},
		},
	}).Create(owner); err != nil {
		return "", "", false
	}
	refreshPub()
	dlg.Run()
	return resText, resName, ok
}
