#!/bin/sh
# Собирает Go-часть клиента в android/app/libs/xsteer.aar.
#
# Запускается из каталога mobile: у моста свой модуль Go, потому что gomobile требует
# golang.org/x/mobile в графе зависимостей, а тот требует Go 1.26 и тащит четыре чужие
# зависимости. Подробнее — в mobile/go.mod.
#
# Нужны Android SDK и NDK. В отличие от iOS, никакого Mac здесь не требуется: собирается на
# любой системе, где есть Go и NDK.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
out="$here/app/libs"

command -v go >/dev/null 2>&1 || { echo "нет go" >&2; exit 1; }

: "${ANDROID_HOME:=${ANDROID_SDK_ROOT:-}}"
if [ -z "$ANDROID_HOME" ]; then
    echo "build-aar.sh: не задан ANDROID_HOME (или ANDROID_SDK_ROOT)" >&2
    exit 1
fi
export ANDROID_HOME

# NDK ищется сам: у разных установок он лежит под разными номерами версий, и записывать номер
# в скрипт значило бы ломать сборку при каждом обновлении.
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    ANDROID_NDK_HOME=$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1 || true)
fi
if [ -z "$ANDROID_NDK_HOME" ] || [ ! -d "$ANDROID_NDK_HOME" ]; then
    echo "build-aar.sh: не нашёл NDK. Поставьте его: sdkmanager 'ndk;27.2.12479018'" >&2
    exit 1
fi
export ANDROID_NDK_HOME

cd "$root/mobile"

# gomobile и gobind зовутся через `go tool`, а не из GOPATH/bin: так их версия берётся из
# mobile/go.mod и совпадает с версией x/mobile, с которой собран мост.
echo "== gomobile init =="
go tool gomobile init

mkdir -p "$out"
rm -f "$out/xsteer.aar" "$out/xsteer-sources.jar"

echo "== собираю xsteer.aar =="
# Четыре архитектуры: два ARM покрывают телефоны, два x86 — эмуляторы и редкие планшеты.
# Минимальный уровень 24 тот же, что у приложения: ниже Go всё равно не поддерживает.
go tool gomobile bind \
    -target=android/arm64,android/arm,android/amd64,android/386 \
    -androidapi 24 \
    -o "$out/xsteer.aar" \
    -ldflags="-s -w" \
    .

echo "== готово =="
ls -la "$out"
