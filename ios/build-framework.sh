#!/bin/sh
# Собирает Go-часть клиента в Xsteer.xcframework, который подключают оба целевых файла
# Xcode. Запускать только на macOS: gomobile зовёт clang из Xcode и lipo, а ни того, ни
# другого на других системах нет.
#
# ЗАЧЕМ ОТДЕЛЬНЫЙ ШАГ, А НЕ ПРАВИЛО В XCODE. Сборка Go занимает минуты и не зависит ни от
# схемы, ни от конфигурации — а Xcode пересобирал бы её на каждый запуск. Плюс правило
# внутри проекта требует снять песочницу пользовательских сценариев, то есть ослабить
# сборку ради удобства.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
out="$root/mobile/build"

case "$(uname -s)" in
Darwin) ;;
*)
    echo "build-framework.sh: нужен macOS с Xcode — gomobile зовёт clang и lipo." >&2
    echo "Своего Mac нет: сборку делает .github/workflows/ios.yml на бегунке macOS." >&2
    exit 1
    ;;
esac

command -v go >/dev/null 2>&1 || { echo "нет go" >&2; exit 1; }
xcode-select -p >/dev/null 2>&1 || { echo "нет Xcode (xcode-select -p)" >&2; exit 1; }

# gomobile ставится в GOPATH/bin, которого может не быть в PATH.
gobin=$(go env GOPATH)/bin
PATH="$gobin:$PATH"
export PATH

if ! command -v gomobile >/dev/null 2>&1; then
    echo "== ставлю gomobile =="
    go install golang.org/x/mobile/cmd/gomobile@latest
    go install golang.org/x/mobile/cmd/gobind@latest
fi

# gomobile init нужен один раз на машину; повторный вызов дешёв и не мешает.
gomobile init

mkdir -p "$out"
rm -rf "$out/Xsteer.xcframework"

echo "== собираю Xsteer.xcframework =="
cd "$root"
# -target=ios даёт устройство и симулятор в одном xcframework: без симулятора проект не
# собрать на проверке без подписи, а именно она и гоняется в Actions на каждый коммит.
# Имя пакета в Swift берётся из -javapkg только для Android; в Swift модуль называется по
# имени выходного файла, поэтому он Xsteer.
gomobile bind \
    -target=ios,iossimulator \
    -o "$out/Xsteer.xcframework" \
    -ldflags="-s -w" \
    ./mobile

echo "== готово =="
ls -la "$out"
