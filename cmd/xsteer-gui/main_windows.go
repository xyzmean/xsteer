//go:build windows

// xsteer-gui — управляющий интерфейс для Windows.
//
// ЧТО ЭТО И ЧЕГО НЕ ДЕЛАЕТ. Это тонкая оболочка над xsteer.exe, а не второй клиент: сам туннель
// по-прежнему ведёт xsteer.exe, а окно показывает список конфигураций, поднимает и снимает
// выбранную и рисует её состояние. Так у десктопного человека появляется то, ради чего ставят
// WireGuard именно с интерфейсом: список туннелей, кнопка «подключить» и видимое состояние — без
// командной строки и без запоминания ключей.
//
// РАСКЛАДКА ВЗЯТА С AmneziaWG, и намеренно: человек, у которого он уже стоит, не должен здесь
// ничего изучать заново. Отсюда две закладки (туннели и журнал), разбор конфигурации на понятные
// поля в двух рамках («Интерфейс» и «Пир») вместо простыни текста, правка в отдельном окне по
// кнопке, а не вечно открытый редактор, и список слева с точкой состояния у каждого туннеля.
//
// ПОЧЕМУ walk. Тот же набор (lxn/walk поверх Win32), на котором сделан менеджер WireGuard для
// Windows: родные элементы управления, без своего рантайма и без Electron. Манифест (общие
// элементы управления v6 и требование прав администратора) вшит ресурсом — без прав не создать
// устройство Wintun, без манифеста walk не поднимет окно.
//
// ОДИН ТУННЕЛЬ ЗА РАЗ. Полный туннель по определению один: два маршрута по умолчанию не уживаются.
// Поэтому подключение нового сначала снимает прежний — как и в WireGuard.
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

// rsrc_windows_amd64.syso несёт манифест и значок .exe. Он лежит в репозитории готовым, чтобы
// обычная `go build` его подхватила без внешних инструментов. Пересоздать при смене манифеста:
//
//go:generate go run github.com/akavel/rsrc@v0.10.2 -manifest xsteer-gui.exe.manifest -ico xsteer.ico -o rsrc_windows_amd64.syso

//go:embed xsteer.png
var iconPNG []byte

// Цвета точки состояния: зелёная — несёт трафик, жёлтая — поднимается, серая — снят.
var (
	colorUp      = walk.RGB(0x2e, 0xa0, 0x43)
	colorPending = walk.RGB(0xc8, 0x8a, 0x00)
	colorDown    = walk.RGB(0x88, 0x88, 0x88)
)

// state — то, что xsteer.exe пишет в файл по ключу --state. Копия полей из client.State: тянуть
// пакет client в интерфейс ради семи полей не стоит.
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
	mw   *walk.MainWindow
	ni   *walk.NotifyIcon
	tabs *walk.TabWidget
	list *walk.ListBox

	// Рамка «Интерфейс»: заголовок несёт имя туннеля, как в эталоне.
	gbIface *walk.GroupBox
	dot     *walk.Label
	stState *walk.Label
	stPub   *walk.TextLabel
	stMTU   *walk.Label
	stAddrs *walk.Label
	stDNS   *walk.Label
	stShake *walk.Label
	stMove  *walk.Label

	// Рамка «Пир».
	pPub     *walk.TextLabel
	pAllowed *walk.TextLabel
	pServer  *walk.Label

	btnToggle *walk.PushButton
	btnEdit   *walk.PushButton
	logView   *walk.TextEdit

	names    []string // имена туннелей в порядке списка
	confDir  string
	stateDir string
	exeDir   string
	logSize  int64 // сколько журнала уже показано, чтобы не перерисовывать зря

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

	// Ширина колонки значений задана явно, и у TextLabel она же включает перенос строк: ключи и
	// длинный список AllowedIPs обязаны переноситься, а не растягивать окно.
	const valW = 330

	if err := (dcl.MainWindow{
		AssignTo: &a.mw,
		Title:    "xsteer",
		Icon:     icon,
		MinSize:  dcl.Size{Width: 820, Height: 600},
		Size:     dcl.Size{Width: 900, Height: 640},
		Layout:   dcl.VBox{MarginsZero: true},
		MenuItems: []dcl.MenuItem{
			dcl.Menu{
				Text: "&Туннель",
				Items: []dcl.MenuItem{
					dcl.Action{Text: "&Добавить из файла…", OnTriggered: a.onImport},
					dcl.Action{Text: "&Новый пустой…", OnTriggered: a.onNew},
					dcl.Separator{},
					dcl.Action{Text: "&Редактировать…", OnTriggered: a.onEdit},
					dcl.Action{Text: "&Удалить", OnTriggered: a.onDelete},
					dcl.Separator{},
					dcl.Action{Text: "Открыть &папку конфигураций", OnTriggered: a.onFolder},
					dcl.Separator{},
					dcl.Action{Text: "&Свернуть в трей", OnTriggered: func() { a.mw.Hide() }},
					dcl.Action{Text: "В&ыход", OnTriggered: a.quit},
				},
			},
		},
		Children: []dcl.Widget{
			dcl.TabWidget{
				AssignTo: &a.tabs,
				Pages: []dcl.TabPage{
					{
						Title:  "Туннели",
						Layout: dcl.HBox{},
						Children: []dcl.Widget{
							// ---- слева: список туннелей и действия под ним ---------------
							dcl.Composite{
								Layout:  dcl.VBox{MarginsZero: true},
								MinSize: dcl.Size{Width: 230},
								Children: []dcl.Widget{
									dcl.ListBox{
										AssignTo:              &a.list,
										OnCurrentIndexChanged: a.onSelect,
									},
									dcl.Composite{
										Layout: dcl.HBox{MarginsZero: true, Spacing: 4},
										Children: []dcl.Widget{
											dcl.PushButton{Text: "Добавить туннель", OnClicked: a.onImport},
											dcl.PushButton{Text: "Удалить", MaxSize: dcl.Size{Width: 84},
												OnClicked: a.onDelete},
										},
									},
								},
							},
							// ---- справа: разобранная конфигурация и состояние ------------
							dcl.Composite{
								StretchFactor: 2,
								Layout:        dcl.VBox{MarginsZero: true},
								Children: []dcl.Widget{
									dcl.GroupBox{
										AssignTo: &a.gbIface,
										Title:    "Интерфейс",
										Layout:   dcl.Grid{Columns: 3, Spacing: 6},
										Children: []dcl.Widget{
											// Третья колонка — распорка. Без неё сетка сжимается по
											// содержимому, и рамка висит узкой полосой не на всю
											// ширину: именно это было видно на первом снимке.
											dcl.Label{Text: "Статус:", TextAlignment: dcl.AlignFar,
												MinSize: dcl.Size{Width: 160}},
											dcl.Composite{
												Layout: dcl.HBox{MarginsZero: true, Spacing: 4},
												Children: []dcl.Widget{
													dcl.Label{AssignTo: &a.dot, Text: "●", TextColor: colorDown},
													dcl.Label{AssignTo: &a.stState, Text: "—"},
													dcl.HSpacer{},
												},
											},
											dcl.HSpacer{},

											dcl.Label{Text: "Публичный ключ:", TextAlignment: dcl.AlignFar},
											dcl.TextLabel{AssignTo: &a.stPub, Text: "—",
												MinSize: dcl.Size{Width: valW}},
											dcl.HSpacer{},

											dcl.Label{Text: "MTU:", TextAlignment: dcl.AlignFar},
											dcl.Label{AssignTo: &a.stMTU, Text: "—"},
											dcl.HSpacer{},

											dcl.Label{Text: "IP-адреса:", TextAlignment: dcl.AlignFar},
											dcl.Label{AssignTo: &a.stAddrs, Text: "—"},
											dcl.HSpacer{},

											dcl.Label{Text: "DNS-серверы:", TextAlignment: dcl.AlignFar},
											dcl.Label{AssignTo: &a.stDNS, Text: "—"},
											dcl.HSpacer{},

											// Двух строк ниже у эталона нет, а они здесь самые
											// полезные: живое подтверждение, что канал несёт
											// трафик, а не просто «поднят».
											dcl.Label{Text: "Соединение поднято:", TextAlignment: dcl.AlignFar},
											dcl.Label{AssignTo: &a.stShake, Text: "—"},
											dcl.HSpacer{},

											dcl.Label{Text: "Передача:", TextAlignment: dcl.AlignFar},
											dcl.Label{AssignTo: &a.stMove, Text: "—"},
											dcl.HSpacer{},

											dcl.HSpacer{},
											dcl.Composite{
												Layout: dcl.HBox{MarginsZero: true},
												Children: []dcl.Widget{
													dcl.PushButton{AssignTo: &a.btnToggle, Text: "Подключить",
														MinSize: dcl.Size{Width: 140}, OnClicked: a.onToggle},
													dcl.HSpacer{},
												},
											},
											dcl.HSpacer{},
										},
									},
									dcl.GroupBox{
										Title:  "Пир",
										Layout: dcl.Grid{Columns: 3, Spacing: 6},
										Children: []dcl.Widget{
											dcl.Label{Text: "Публичный ключ:", TextAlignment: dcl.AlignFar,
												MinSize: dcl.Size{Width: 160}},
											dcl.TextLabel{AssignTo: &a.pPub, Text: "—",
												MinSize: dcl.Size{Width: valW}},
											dcl.HSpacer{},

											dcl.Label{Text: "Разрешённые IP-адреса:", TextAlignment: dcl.AlignFar},
											dcl.TextLabel{AssignTo: &a.pAllowed, Text: "—",
												MinSize: dcl.Size{Width: valW}},
											dcl.HSpacer{},

											dcl.Label{Text: "IP-адрес сервера:", TextAlignment: dcl.AlignFar},
											dcl.Label{AssignTo: &a.pServer, Text: "—"},
											dcl.HSpacer{},
										},
									},
									dcl.VSpacer{},
									dcl.Composite{
										Layout: dcl.HBox{MarginsZero: true},
										Children: []dcl.Widget{
											dcl.HSpacer{},
											dcl.PushButton{AssignTo: &a.btnEdit, Text: "Редактировать",
												MinSize: dcl.Size{Width: 140}, OnClicked: a.onEdit},
										},
									},
								},
							},
						},
					},
					{
						Title:  "Журнал",
						Layout: dcl.VBox{},
						Children: []dcl.Widget{
							// Журнал показывается текстом, а не таблицей: строки пишет сам клиент в
							// файл, и разбирать свой же вывод на колонки значило бы ломаться от
							// каждой правки формулировки в журнале.
							dcl.TextEdit{
								AssignTo: &a.logView,
								ReadOnly: true,
								VScroll:  true,
								HScroll:  true,
								Font:     dcl.Font{Family: "Consolas", PointSize: 9},
							},
							dcl.Composite{
								Layout: dcl.HBox{MarginsZero: true},
								Children: []dcl.Widget{
									dcl.PushButton{Text: "Открыть папку", OnClicked: a.onFolder},
									dcl.HSpacer{},
									dcl.PushButton{Text: "Сохранить", MinSize: dcl.Size{Width: 140},
										OnClicked: a.onSaveLog},
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

	// Трей: закрытие окна прячет его туда, а не завершает — как у WireGuard, где менеджер
	// продолжает держать туннель и после закрытия окна.
	a.setupTray(icon)
	a.mw.Closing().Attach(func(canceled *bool, reason walk.CloseReason) {
		if reason == walk.CloseReasonUser {
			*canceled = true
			a.mw.Hide()
		}
	})

	a.refresh()
	a.onSelect()

	// Опрос раз в секунду: состояние и журнал активного туннеля. Всё в потоке окна через
	// Synchronize — walk не терпит доступа к элементам из чужой горутины.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for range t.C {
			a.mw.Synchronize(func() {
				a.updateStatus()
				a.updateLog()
			})
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

// refresh перечитывает каталог конфигураций в список, сохраняя выбор. Точка состояния рисуется
// прямо в строке: у поднятого туннеля она закрашена, у остальных пустая.
func (a *app) refresh() {
	was := a.selected()
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

	a.mu.Lock()
	active := a.active
	a.mu.Unlock()
	shown := make([]string, len(a.names))
	for i, n := range a.names {
		if n == active {
			shown[i] = "● " + n
		} else {
			shown[i] = "○ " + n
		}
	}
	a.list.SetModel(shown)
	if was != "" {
		a.selectByName(was)
	} else if len(a.names) > 0 {
		a.list.SetCurrentIndex(0)
	}
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
func (a *app) logPath(name string) string   { return filepath.Join(a.stateDir, name+".log") }

func (a *app) selectByName(name string) {
	for i, n := range a.names {
		if n == name {
			a.list.SetCurrentIndex(i)
			return
		}
	}
}

// onSelect перерисовывает обе рамки по выбранной конфигурации.
func (a *app) onSelect() {
	name := a.selected()
	if name == "" {
		a.gbIface.SetTitle("Интерфейс")
		for _, l := range []*walk.TextLabel{a.stPub, a.pPub, a.pAllowed} {
			l.SetText("—")
		}
		for _, l := range []*walk.Label{a.stMTU, a.stAddrs, a.stDNS, a.pServer} {
			l.SetText("—")
		}
		a.updateStatus()
		a.updateButtons()
		return
	}
	a.gbIface.SetTitle("Интерфейс: " + name)
	c := parseConf(readText(a.confPath(name)))
	a.stPub.SetText(dash(c.SelfPub))
	a.stMTU.SetText(dashDefault(c.MTU, "согласуется сам"))
	a.stAddrs.SetText(dash(c.Address))
	a.stDNS.SetText(dashDefault(c.DNS, "не заданы"))
	a.pPub.SetText(dash(c.PeerPub))
	a.pAllowed.SetText(dash(c.Allowed))
	a.pServer.SetText(dash(c.Endpoint))
	a.logSize = -1 // журнал перечитать заново: туннель другой
	a.updateStatus()
	a.updateButtons()
	a.updateLog()
}

func (a *app) updateButtons() {
	a.mu.Lock()
	active := a.active
	a.mu.Unlock()
	sel := a.selected()
	a.btnToggle.SetEnabled(sel != "")
	a.btnEdit.SetEnabled(sel != "")
	if sel != "" && active == sel {
		a.btnToggle.SetText("Отключить")
	} else {
		a.btnToggle.SetText("Подключить")
	}
}

func (a *app) onToggle() {
	a.mu.Lock()
	active := a.active
	a.mu.Unlock()
	sel := a.selected()
	if sel == "" {
		return
	}
	if active == sel {
		a.disconnectNow()
	} else if err := a.connect(sel); err != nil {
		walk.MsgBox(a.mw, "xsteer", "не подключилось: "+err.Error(), walk.MsgBoxIconError)
	}
	a.refresh()
	a.updateButtons()
	a.updateStatus()
}

// updateStatus рисует живые поля: точку, словесное состояние, возраст соединения и счётчики.
func (a *app) updateStatus() {
	a.mu.Lock()
	active := a.active
	a.mu.Unlock()
	name := a.selected()

	if name == "" || active != name {
		a.dot.SetTextColor(colorDown)
		a.stState.SetText("отключён")
		a.stShake.SetText("—")
		a.stMove.SetText("—")
		a.trayTip("xsteer — отключён")
		return
	}
	st, err := readState(a.statePath(name))
	if err != nil || !st.Up {
		a.dot.SetTextColor(colorPending)
		a.stState.SetText("подключается…")
		if err == nil {
			a.stShake.SetText(since(st.HandshakeAge))
		}
		a.trayTip("xsteer — " + name + " (подключается)")
		return
	}
	a.dot.SetTextColor(colorUp)
	word := "подключён"
	if st.Conns > 1 {
		word = fmt.Sprintf("подключён, соединений %d", st.Conns)
	}
	a.stState.SetText(word)
	if st.MTU > 0 {
		a.stMTU.SetText(fmt.Sprint(st.MTU))
	}
	if st.Device != "" {
		a.gbIface.SetTitle("Интерфейс: " + name + " (" + st.Device + ")")
	}
	a.stShake.SetText(since(st.HandshakeAge))
	a.stMove.SetText(fmt.Sprintf("↓ %s   ↑ %s", human(st.RXBytes), human(st.TXBytes)))
	a.trayTip("xsteer — " + name + " (подключён)")
}

// updateLog подтягивает журнал выбранного туннеля, только если он вырос: SetText на каждом такте
// сбрасывал бы позицию прокрутки и выделение.
func (a *app) updateLog() {
	name := a.selected()
	if name == "" {
		return
	}
	fi, err := os.Stat(a.logPath(name))
	if err != nil {
		if a.logSize != 0 {
			a.logView.SetText("")
			a.logSize = 0
		}
		return
	}
	if fi.Size() == a.logSize {
		return
	}
	a.logSize = fi.Size()
	b, err := os.ReadFile(a.logPath(name))
	if err != nil {
		return
	}
	a.logView.SetText(strings.ReplaceAll(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n", "\r\n"))
}

func (a *app) onSaveLog() {
	name := a.selected()
	if name == "" {
		return
	}
	dlg := &walk.FileDialog{Title: "Сохранить журнал",
		Filter: "Текст (*.txt)|*.txt|Все файлы (*.*)|*.*", FilePath: name + ".txt"}
	ok, err := dlg.ShowSave(a.mw)
	if err != nil || !ok {
		return
	}
	b, err := os.ReadFile(a.logPath(name))
	if err != nil {
		walk.MsgBox(a.mw, "xsteer", "журнала пока нет", walk.MsgBoxIconWarning)
		return
	}
	if err := os.WriteFile(dlg.FilePath, b, 0600); err != nil {
		walk.MsgBox(a.mw, "xsteer", "не сохранилось: "+err.Error(), walk.MsgBoxIconError)
	}
}

func (a *app) onFolder() { _ = exec.Command("explorer.exe", a.confDir).Start() }

func (a *app) onImport() {
	dlg := &walk.FileDialog{Title: "Добавить туннель из файла",
		Filter: "Конфигурации xsteer (*.conf)|*.conf|Все файлы (*.*)|*.*"}
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
	a.onSelect()
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
	a.onSelect()
	a.onEdit()
}

// onEdit открывает правку в отдельном окне — как в эталоне. Вечно открытый редактор в главном окне
// занимал половину места и провоцировал правку поднятого туннеля «на ходу».
func (a *app) onEdit() {
	name := a.selected()
	if name == "" {
		return
	}
	text, newName, ok := editTunnel(a.mw, name, readText(a.confPath(name)))
	if !ok {
		return
	}
	if err := os.WriteFile(a.confPath(name), []byte(text), 0600); err != nil {
		walk.MsgBox(a.mw, "xsteer", "не сохранилось: "+err.Error(), walk.MsgBoxIconError)
		return
	}
	if newName != "" && newName != name {
		if _, err := os.Stat(a.confPath(newName)); err == nil {
			walk.MsgBox(a.mw, "xsteer", "туннель «"+newName+"» уже есть — имя оставлено прежним",
				walk.MsgBoxIconWarning)
		} else if err := os.Rename(a.confPath(name), a.confPath(newName)); err == nil {
			a.mu.Lock()
			if a.active == name {
				a.active = newName
			}
			a.mu.Unlock()
			name = newName
		}
	}
	a.refresh()
	a.selectByName(name)
	a.onSelect()

	a.mu.Lock()
	active := a.active
	a.mu.Unlock()
	if active == name {
		walk.MsgBox(a.mw, "xsteer",
			"Сохранено. Туннель поднят — чтобы новые настройки применились, переподключите его.",
			walk.MsgBoxIconInformation)
	}
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
	os.Remove(a.logPath(name))
	a.refresh()
	a.onSelect()
}

// connect поднимает туннель name. Прежний, если был, снимается: полный туннель один.
func (a *app) connect(name string) error {
	a.disconnectNow()
	exe := filepath.Join(a.exeDir, "xsteer.exe")
	if _, err := os.Stat(exe); err != nil {
		return fmt.Errorf("не найден xsteer.exe рядом с интерфейсом (%s)", exe)
	}
	cmd := exec.Command(exe, "up", a.confPath(name), "--dev", "xsteer", "--state", a.statePath(name))
	// Без своего окна консоли: интерфейс запускает клиента невидимо, как служба.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	// Журнал клиента — в файл: закладка «Журнал» показывает именно его, и человеку не нужно
	// поднимать окно консоли, чтобы понять, почему не поднялось.
	if lf, err := os.Create(a.logPath(name)); err == nil {
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
	a.logSize = -1
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
