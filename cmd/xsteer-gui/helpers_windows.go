//go:build windows

package main

import (
	"encoding/json"
	"os"
	"regexp"

	"github.com/lxn/walk"
	dcl "github.com/lxn/walk/declarative"
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

var nameOK = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,32}$`)

// promptName — маленький модальный ввод имени туннеля. walk своего InputBox не даёт, а имя нужно
// проверить сразу: оно станет именем файла, поэтому набор символов ограничен.
func promptName(owner walk.Form) (string, bool) {
	var dlg *walk.Dialog
	var edit *walk.LineEdit
	var okBtn, cancelBtn *walk.PushButton
	res := ""

	err := (dcl.Dialog{
		AssignTo:      &dlg,
		Title:         "Имя туннеля",
		DefaultButton: &okBtn,
		CancelButton:  &cancelBtn,
		MinSize:       dcl.Size{Width: 320, Height: 120},
		Layout:        dcl.VBox{},
		Children: []dcl.Widget{
			dcl.Label{Text: "Буквы, цифры, дефис, подчёркивание и точка; до 32 символов."},
			dcl.LineEdit{AssignTo: &edit},
			dcl.Composite{
				Layout: dcl.HBox{},
				Children: []dcl.Widget{
					dcl.HSpacer{},
					dcl.PushButton{
						AssignTo: &okBtn,
						Text:     "ОК",
						OnClicked: func() {
							v := edit.Text()
							if !nameOK.MatchString(v) {
								walk.MsgBox(dlg, "xsteer", "недопустимое имя", walk.MsgBoxIconWarning)
								return
							}
							res = v
							dlg.Accept()
						},
					},
					dcl.PushButton{AssignTo: &cancelBtn, Text: "Отмена", OnClicked: func() { dlg.Cancel() }},
				},
			},
		},
	}).Create(owner)
	if err != nil {
		return "", false
	}
	if dlg.Run() == walk.DlgCmdOK {
		return res, true
	}
	return "", false
}
