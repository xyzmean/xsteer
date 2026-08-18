//go:build !windows

// xsteer-gui собирается только под Windows: это оболочка над родными элементами управления
// (lxn/walk поверх Win32). На других системах она бессмысленна, поэтому здесь честная заглушка,
// чтобы `go build ./...` и кросс-проверки не спотыкались на отсутствии Windows API.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "xsteer-gui существует только для Windows")
	os.Exit(1)
}
