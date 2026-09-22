// ОТДЕЛЬНЫЙ МОДУЛЬ, и это не аккуратность ради аккуратности.
//
// gomobile bind требует golang.org/x/mobile в графе зависимостей того модуля, в котором он
// запущен, а сам golang.org/x/mobile требует Go 1.26. Положить его в модуль движка значило бы
// поднять нижнюю границу Go для ВСЕХ, кто собирает xsteer на роутер или на сервер, — ради
// инструмента, который нужен только сборке под iOS и только на macOS. Заодно туда приехали бы
// x/mod, x/sync и x/tools и обновление x/sys, то есть чужие зависимости в модуль, где вся сеть
// написана на стандартной библиотеке.
//
// Цена решения одна: `go test ./...` в корне этот модуль НЕ видит, вложенные модули из перебора
// исключаются. Поэтому его проверки запускаются отдельным шагом — см. .github/workflows/ci.yml.
module github.com/xyzmean/xsteer/mobile

go 1.26.0

require (
	github.com/xyzmean/xsteer v0.0.0
	golang.org/x/crypto v0.55.0
)

require (
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard/windows v1.0.1 // indirect
)

// Движок берётся из этого же дерева, а не из сети: мост и протокол правятся вместе, и версия
// из сети означала бы, что мост собран не с тем кодом, который рядом лежит.
replace github.com/xyzmean/xsteer => ../

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
