//go:build windows

// xsteer-gui — простой управляющий интерфейс для Windows, по образцу WireGuard for Windows.
//
// ЧТО ЭТО И ЧЕГО НЕ ДЕЛАЕТ. Это тонкая оболочка над xsteer.exe, а не второй клиент: сам туннель
// по-прежнему ведёт xsteer.exe, а окно лишь показывает список конфигураций, поднимает и снимает
// выбранную и рисует её состояние. Так у десктопного человека появляется то, ради чего ставят
// WireGuard именно с интерфейсом: список туннелей, кнопка «подключить» и видимое рукопожатие —
// без командной строки и без запоминания ключей.
//
// ПОЧЕМУ walk. Тот же набор (lxn/walk поверх lxn/win), на котором сделан менеджер WireGuard для
// Windows: родные элементы управления, без своего рантайма и без Electron. Зависимость уже была в
// go.mod. Манифест общих элементов управления живёт рядом файлом xsteer-gui.exe.manifest — там же
// требование прав администратора: без них не создать устройство Wintun.
//
// ОДИН ТУННЕЛЬ ЗА РАЗ. Полный туннель по определению один: два маршрута по умолчанию не уживаются.
// Поэтому подключение нового сначала снимает прежний — как и в WireGuard, где активна одна
// конфигурация. Список при этом может быть любой длины.
package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"image"
	_ "image/png"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lxn/walk"
	dcl "github.com/lxn/walk/declarative"
)

// rsrc_windows_amd64.syso несёт манифест (общие элементы управления v6 + требование прав
// администратора) и значок .exe. Он сгенерирован и лежит в репозитории готовым, чтобы обычная
// `go build` его подхватила без внешних инструментов. Пересоздать при смене манифеста или значка:
//
//go:generate go run github.com/akavel/rsrc@v0.10.2 -manifest xsteer-gui.exe.manifest -ico xsteer.ico -o rsrc_windows_amd64.syso

//go:embed xsteer.png
var iconPNG []byte

// state — то, что xsteer.exe пишет в файл состояния по ключу --state. Копия полей из
// client.State: держать общий тип не стоит того, чтобы тянуть пакет client в интерфейс, а полей
// немного и меняются они редко.
type state struct {
	Up           bool   `json:"up"`
	Device       string `json:"device"`
	Conns        int    `json:"conns"`
	MTU          int    `json:"mtu"`
	Hub          string `json:"hub"`
	HandshakeAge int64  `json:"handshake_age"`
	TXBytes      uint64 `json:"tx_bytes"`
	RXBytes      uint64 `json:"rx_bytes"`
}

// app держит всё изменяемое состояние окна в одном месте: так проще рассуждать о том, что
// трогается из таймера, а что — из обработчиков кнопок (всё через mw.Synchronize, в одном потоке).
type app struct {
	mw      *walk.MainWindow
	ni      *walk.NotifyIcon
	list    *walk.ListBox
	editor  *walk.TextEdit
	stName  *walk.Label
	stAddr  *walk.Label
	stHub   *walk.Label
	stShake *walk.Label
	stMove  *walk.Label
	btnUp   *walk.PushButton
	btnDown *walk.PushButton
	btnSave *walk.PushButton

	names    []string // имена туннелей, как в списке
	confDir  string
	stateDir string
	exeDir   string

	mu     sync.Mutex
	active string    // имя поднятого туннеля, пусто — ничего не поднято
	cmd    *exec.Cmd // процесс xsteer.exe активного туннеля
}

func main() {
	a := &app{}
	if err := a.paths(); err != nil {
		walk.MsgBox(nil, "xsteer", "не удалось определить каталоги: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	icon := loadIcon()

	if err := (dcl.MainWindow{
		AssignTo: &a.mw,
		Title:    "xsteer",
		Icon:     icon,
		MinSize:  dcl.Size{Width: 720, Height: 460},
		Size:     dcl.Size{Width: 760, Height: 500},
		Layout:   dcl.VBox{},
		MenuItems: []dcl.MenuItem{
			dcl.Menu{
				Text: "&Туннель",
				Items: []dcl.MenuItem{
					dcl.Action{Text: "&Импортировать из файла…", OnTriggered: a.onImport},
					dcl.Action{Text: "&Новый пустой…", OnTriggered: a.onNew},
					dcl.Separator{},
					dcl.Action{Text: "&Удалить выбранный", OnTriggered: a.onDelete},
					dcl.Separator{},
					dcl.Action{Text: "&Свернуть в трей", OnTriggered: func() { a.mw.Hide() }},
					dcl.Action{Text: "В&ыход", OnTriggered: a.quit},
				},
			},
		},
		Children: []dcl.Widget{
			dcl.HSplitter{
				Children: []dcl.Widget{
					dcl.ListBox{
						AssignTo:              &a.list,
						MinSize:               dcl.Size{Width: 200},
						StretchFactor:         1,
						OnCurrentIndexChanged: a.onSelect,
					},
					dcl.Composite{
						StretchFactor: 3,
						Layout:        dcl.VBox{},
						Children: []dcl.Widget{
							dcl.GroupBox{
								Title:  "Состояние",
								Layout: dcl.Grid{Columns: 2},
								Children: []dcl.Widget{
									dcl.Label{Text: "Состояние:"}, dcl.Label{AssignTo: &a.stName, Text: "—"},
									dcl.Label{Text: "Адрес:"}, dcl.Label{AssignTo: &a.stAddr, Text: "—"},
									dcl.Label{Text: "Хаб:"}, dcl.Label{AssignTo: &a.stHub, Text: "—"},
									dcl.Label{Text: "Рукопожатие:"}, dcl.Label{AssignTo: &a.stShake, Text: "—"},
									dcl.Label{Text: "Передача:"}, dcl.Label{AssignTo: &a.stMove, Text: "—"},
								},
							},
							dcl.Composite{
								Layout: dcl.HBox{},
								Children: []dcl.Widget{
									dcl.PushButton{AssignTo: &a.btnUp, Text: "Подключить", OnClicked: a.onConnect},
									dcl.PushButton{AssignTo: &a.btnDown, Text: "Отключить", OnClicked: a.onDisconnect},
									dcl.HSpacer{},
								},
							},
							dcl.GroupBox{
								Title:         "Конфигурация",
								Layout:        dcl.VBox{},
								StretchFactor: 1,
								Children: []dcl.Widget{
									dcl.TextEdit{AssignTo: &a.editor, VScroll: true, Font: dcl.Font{Family: "Consolas", PointSize: 10}},
									dcl.Composite{
										Layout: dcl.HBox{},
										Children: []dcl.Widget{
											dcl.HSpacer{},
											dcl.PushButton{AssignTo: &a.btnSave, Text: "Сохранить", OnClicked: a.onSave},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}).Create(); err != nil {
		walk.MsgBox(nil, "xsteer", "окно не создалось: "+err.Error(), walk.MsgBoxIconError)
		return
	}

	// Трей: иконка с меню. Закрытие окна прячет его в трей, а не завершает — как у WireGuard, где
	// менеджер продолжает держать туннель и после закрытия окна.
	a.setupTray(icon)
	a.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if reason == walk.CloseReasonUser {
			*canceled = true
			a.mw.Hide()
		}
	})

	a.refresh()
	a.updateButtons()

	// Опрос состояния: раз в секунду читаем файл состояния активного туннеля и обновляем метки.
	// Всё в потоке окна через Synchronize — walk не терпит доступа к элементам из чужой горутины.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for range t.C {
			a.mw.Synchronize(a.updateStatus)
		}
	}()

	a.mw.Run()
}

// paths раскладывает рабочие каталоги. Конфигурации и состояние — в %APPDATA%\xsteer; xsteer.exe
// ищется рядом с этим бинарником, потому что в архив они кладутся вместе.
func (a *app) paths() error {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	a.confDir = filepath.Join(cfg, "xsteer", "tunnels")
	a.stateDir = filepath.Join(cfg, "xsteer", "state")
	if err := os.MkdirAll(a.confDir, 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(a.stateDir, 0700); err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	a.exeDir = filepath.Dir(exe)
	return nil
}

func loadIcon() *walk.Icon {
	img, _, err := image.Decode(bytes.NewReader(iconPNG))
	if err != nil {
		return nil
	}
	ic, err := walk.NewIconFromImage(img)
	if err != nil {
		return nil
	}
	return ic
}

func (a *app) setupTray(icon *walk.Icon) {
	ni, err := walk.NewNotifyIcon(a.mw)
	if err != nil {
		return
	}
	a.ni = ni
	if icon != nil {
		ni.SetIcon(icon)
	}
	ni.SetToolTip("xsteer")
	ni.SetVisible(true)
	// Двойной клик по иконке — показать окно.
	ni.MouseDown().Attach(func(x, y int, button walk.MouseButton) {
		if button == walk.LeftButton {
			a.show()
		}
	})
	show := walk.NewAction()
	show.SetText("Показать")
	show.Triggered().Attach(a.show)
	ni.ContextMenu().Actions().Add(show)
	quit := walk.NewAction()
	quit.SetText("Выход")
	quit.Triggered().Attach(a.quit)
	ni.ContextMenu().Actions().Add(quit)
}

func (a *app) show() {
	a.mw.Show()
	a.mw.SetFocus()
}

func (a *app) quit() {
	a.disconnectNow()
	if a.ni != nil {
		a.ni.SetVisible(false)
	}
	walk.App().Exit(0)
}

// refresh перечитывает каталог конфигураций в список.
func (a *app) refresh() {
	entries, _ := os.ReadDir(a.confDir)
	a.names = a.names[:0]
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".conf") {
			a.names = append(a.names, strings.TrimSuffix(e.Name(), filepath.Ext(e.Name())))
		}
	}
	sort.Strings(a.names)
	a.list.SetModel(a.names)
}

func (a *app) selected() string {
	i := a.list.CurrentIndex()
	if i < 0 || i >= len(a.names) {
		return ""
	}
	return a.names[i]
}

func (a *app) confPath(name string) string  { return filepath.Join(a.confDir, name+".conf") }
func (a *app) statePath(name string) string { return filepath.Join(a.stateDir, name+".json") }

func (a *app) onSelect() {
	name := a.selected()
	if name == "" {
		a.editor.SetText("")
		return
	}
	b, err := os.ReadFile(a.confPath(name))
	if err != nil {
		a.editor.SetText("")
	} else {
		// walk хочет CRLF в многострочном поле, иначе строки склеиваются.
		a.editor.SetText(strings.ReplaceAll(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n", "\r\n"))
	}
	a.updateButtons()
	a.updateStatus()
}

func (a *app) onSave() {
	name := a.selected()
	if name == "" {
		return
	}
	text := strings.ReplaceAll(a.editor.Text(), "\r\n", "\n")
	if err := os.WriteFile(a.confPath(name), []byte(text), 0600); err != nil {
		walk.MsgBox(a.mw, "xsteer", "не сохранилось: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	a.mu.Lock()
	active := a.active
	a.mu.Unlock()
	if active == name {
		walk.MsgBox(a.mw, "xsteer",
			"Сохранено. Туннель поднят — чтобы новые настройки применились, переподключите его.",
			walk.MsgBoxIconInformation)
	}
}

func (a *app) onImport() {
	dlg := &walk.FileDialog{Title: "Импорт конфигурации", Filter: "Конфигурации xsteer (*.conf)|*.conf|Все файлы (*.*)|*.*"}
	ok, err := dlg.ShowOpen(a.mw)
	if err != nil || !ok {
		return
	}
	name := strings.TrimSuffix(filepath.Base(dlg.FilePath), filepath.Ext(dlg.FilePath))
	b, err := os.ReadFile(dlg.FilePath)
	if err != nil {
		walk.MsgBox(a.mw, "xsteer", "файл не прочитался: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	if err := os.WriteFile(a.confPath(name), b, 0600); err != nil {
		walk.MsgBox(a.mw, "xsteer", "не записалось: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	a.refresh()
	a.selectByName(name)
}

func (a *app) onNew() {
	name, ok := promptName(a.mw)
	if !ok || name == "" {
		return
	}
	if _, err := os.Stat(a.confPath(name)); err == nil {
		walk.MsgBox(a.mw, "xsteer", "туннель с таким именем уже есть", walk.MsgBoxIconWarning)
		return
	}
	tmpl := "[Interface]\nPrivateKey = \nAddress = 10.9.0.2/24\nSNI = www.microsoft.com\n\n" +
		"[Peer]\nPublicKey = \nAllowedIPs = 0.0.0.0/0\nEndpoint = ВАШ_ХАБ:3389\nPersistentKeepalive = 25\n"
	if err := os.WriteFile(a.confPath(name), []byte(tmpl), 0600); err != nil {
		walk.MsgBox(a.mw, "xsteer", "не создалось: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	a.refresh()
	a.selectByName(name)
}

func (a *app) onDelete() {
	name := a.selected()
	if name == "" {
		return
	}
	if walk.MsgBox(a.mw, "xsteer", "Удалить туннель «"+name+"»? Файл конфигурации будет стёрт.",
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	a.mu.Lock()
	active := a.active
	a.mu.Unlock()
	if active == name {
		a.disconnectNow()
	}
	os.Remove(a.confPath(name))
	os.Remove(a.statePath(name))
	a.refresh()
}

func (a *app) selectByName(name string) {
	for i, n := range a.names {
		if n == name {
			a.list.SetCurrentIndex(i)
			return
		}
	}
}

func (a *app) onConnect() {
	name := a.selected()
	if name == "" {
		return
	}
	if err := a.connect(name); err != nil {
		walk.MsgBox(a.mw, "xsteer", "не подключилось: "+err.Error(), walk.MsgBoxIconError)
	}
	a.updateButtons()
}

func (a *app) onDisconnect() {
	a.disconnectNow()
	a.updateButtons()
	a.updateStatus()
}

// connect поднимает туннель name. Прежний, если был, снимается: полный туннель один.
func (a *app) connect(name string) error {
	a.disconnectNow()
	exe := filepath.Join(a.exeDir, "xsteer.exe")
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("не найден xsteer.exe рядом с интерфейсом (%s)", exe)
	}
	dev := "xsteer"
	cmd := exec.Command(exe, "up", a.confPath(name), "--dev", dev, "--state", a.statePath(name))
	// Без своего окна консоли: интерфейс запускает клиента невидимо, как служба.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	// Журнал клиента — в файл рядом с состоянием: если рукопожатие не проходит, человеку есть куда
	// посмотреть, а окно консоли ему для этого поднимать не нужно.
	if lf, err := os.Create(filepath.Join(a.stateDir, name+".log")); err == nil {
		cmd.Stdout = lf
		cmd.Stderr = lf
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	a.mu.Lock()
	a.active = name
	a.cmd = cmd
	a.mu.Unlock()
	return nil
}

// disconnectNow снимает активный туннель, если он есть. Безопасна к повторному вызову.
func (a *app) disconnectNow() {
	a.mu.Lock()
	cmd := a.cmd
	a.active = ""
	a.cmd = nil
	a.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
}

func (a *app) updateButtons() {
	a.mu.Lock()
	active := a.active
	a.mu.Unlock()
	sel := a.selected()
	a.btnUp.SetEnabled(sel != "" && active != sel)
	a.btnDown.SetEnabled(sel != "" && active == sel)
}

func (a *app) updateStatus() {
	a.mu.Lock()
	active := a.active
	a.mu.Unlock()
	name := a.selected()
	if name == "" {
		a.setStatus("—", "—", "—", "—", "—")
		return
	}
	if active != name {
		a.setStatus("отключён", "—", "—", "—", "—")
		a.trayTip("xsteer — отключён")
		return
	}
	st, err := readState(a.statePath(name))
	if err != nil {
		a.setStatus("поднимается…", "—", "—", "—", "—")
		return
	}
	shake := "нет"
	if st.HandshakeAge > 0 {
		shake = fmt.Sprintf("%d с назад", st.HandshakeAge)
	}
	stateWord := "поднимается…"
	if st.Up {
		stateWord = "подключён"
	}
	a.setStatus(stateWord, st.Device, st.Hub, shake,
		fmt.Sprintf("↓ %s   ↑ %s", human(st.RXBytes), human(st.TXBytes)))
	a.trayTip("xsteer — " + name + " (" + stateWord + ")")
}

func (a *app) setStatus(name, addr, hub, shake, move string) {
	a.stName.SetText(name)
	a.stAddr.SetText(addr)
	a.stHub.SetText(hub)
	a.stShake.SetText(shake)
	a.stMove.SetText(move)
}

func (a *app) trayTip(s string) {
	if a.ni != nil {
		a.ni.SetToolTip(s)
	}
}

func human(b uint64) string {
	const u = 1024
	if b < u {
		return fmt.Sprintf("%d Б", b)
	}
	div, exp := uint64(u), 0
	for n := b / u; n >= u; n /= u {
		div *= u
		exp++
	}
	pfx := []rune("КМГТ")
	return fmt.Sprintf("%.1f %ciБ", float64(b)/float64(div), pfx[exp])
}
