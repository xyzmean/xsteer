#!/bin/sh
# Собирает Go-часть клиента в Xsteer.xcframework, который подключают оба целевых файла Xcode.
# Запускать только на macOS: gomobile зовёт clang из Xcode и lipo, а ни того, ни другого на
# других системах нет.
#
# ЗАЧЕМ ОТДЕЛЬНЫЙ ШАГ, А НЕ ПРАВИЛО В XCODE. Сборка Go занимает минуты и не зависит ни от схемы,
# ни от конфигурации — а Xcode пересобирал бы её на каждый запуск. Плюс правило внутри проекта
# требует снять песочницу пользовательских сценариев, то есть ослабить сборку ради удобства.
#
# ПОЧЕМУ ЗАПУСК ИЗ mobile/. Мост — отдельный модуль Go: gomobile требует golang.org/x/mobile в
# графе зависимостей своего модуля, а тот требует Go 1.26, и тащить это в модуль движка значило бы
# поднять нижнюю границу Go всем, кто собирает xsteer на роутер. Объяснение целиком — в
# mobile/go.mod.
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

cd "$root/mobile"

# gomobile и gobind зовутся через `go tool`, а не из GOPATH/bin. Так их версия берётся из
# mobile/go.mod, то есть совпадает с версией golang.org/x/mobile, с которой собран мост. С
# `go install …@latest` эти две версии однажды разошлись бы, и отказ был бы невнятным.
echo "== gomobile init =="
go tool gomobile init

mkdir -p "$out"
rm -rf "$out/Xsteer.xcframework"

echo "== собираю Xsteer.xcframework =="
# Устройство и симулятор в одном xcframework: без симулятора проект не собрать на проверке без
# подписи, а именно она и гоняется в Actions на каждый коммит.
go tool gomobile bind \
    -target=ios,iossimulator \
    -o "$out/Xsteer.xcframework" \
    -ldflags="-s -w" \
    .

echo "== готово =="
ls -la "$out"
