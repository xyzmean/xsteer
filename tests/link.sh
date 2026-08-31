#!/bin/sh
# Ссылка xs://: круг «файл → ссылка → файл» и живой туннель, поднятый ПО ССЫЛКЕ.
#
# ЗАЧЕМ ЖИВОЙ ТУННЕЛЬ, А НЕ ТОЛЬКО КРУГ. Круг проверяется набором в conf/link_test.go, и он
# доказывает, что разбор ссылки совпадает с разбором файла. А вот то, что клиент действительно
# принимает ссылку вместо пути — от чтения со стандартного ввода до поднятого устройства, — набором
# не проверяется: там нет ни сети, ни командной строки. Здесь есть и то и другое.
#
#     sudo sh tests/link.sh
set -eu
umask 077

GO=${XSTEER_BIN:-./build/xsteer}
NSH=xsl-hub
NSA=xsl-a
WORK=
fails=0

ok()  { printf '    %-52s ok\n' "$1"; }
bad() { printf '    %-52s ПРОВАЛ %s\n' "$1" "${2:-}"; fails=$((fails + 1)); }

cleanup() {
    for ns in $NSH $NSA; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    [ -n "$WORK" ] && [ -z "${XSL_KEEP:-}" ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT INT TERM PIPE HUP

[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 2; }
[ -c /dev/net/tun ] || { echo "нет /dev/net/tun"; exit 2; }
[ -x "$GO" ] || { echo "нет $GO — соберите: go build -o build/xsteer ./cmd/xsteer"; exit 2; }

WORK="$(mktemp -d)"; chmod 700 "$WORK"
priv_hub=$("$GO" genkey); pub_hub=$(printf '%s\n' "$priv_hub" | "$GO" pubkey)
priv_a=$("$GO" genkey);   pub_a=$(printf '%s\n' "$priv_a" | "$GO" pubkey)
cat > "$WORK/hub.conf" <<EOF
[Interface]
PrivateKey = $priv_hub
Address    = 10.79.0.1/24
ListenPort = 443

[Peer]
PublicKey  = $pub_a
AllowedIPs = 10.79.0.2/32
EOF
cat > "$WORK/a.conf" <<EOF
[Interface]
PrivateKey = $priv_a
Address    = 10.79.0.2/24
SNI        = www.microsoft.com

[Peer]
PublicKey  = $pub_hub
AllowedIPs = 10.79.0.0/24
Endpoint   = 10.212.1.1:443
PersistentKeepalive = 15
EOF
chmod 600 "$WORK"/*.conf

# ---- 1. круг через командную строку ------------------------------------------
"$GO" link "$WORK/a.conf" --name "стенд" > "$WORK/a.link" 2>/dev/null
if grep -q '^xs://' "$WORK/a.link"; then ok "ссылка напечатана"; else bad "ссылка не напечатана"; fi
# Приватный ключ уходит в ВЫВОД, а предупреждение — в ошибку: иначе оно попало бы в файл со ссылкой.
if [ "$(wc -l < "$WORK/a.link")" = 1 ]; then ok "в выводе только ссылка, без предупреждения"
else bad "в выводе больше одной строки"; fi

"$GO" conf - < "$WORK/a.link" > "$WORK/a.back" 2>/dev/null
# Сравниваются не тексты, а СМЫСЛ: порядок ключей и пробелы у печати свои, и сверять их незачем.
# Первая строка вывода check называет путь, а он у двух файлов разный по построению.
norm() { "$GO" check "$1" 2>&1 | grep -v 'разбор прошёл' | grep -v '^ВНИМАНИЕ'; }
chmod 600 "$WORK/a.back"
norm "$WORK/a.conf" > "$WORK/n1"
norm "$WORK/a.back" > "$WORK/n2"
if cmp -s "$WORK/n1" "$WORK/n2"; then
    ok "круг файл → ссылка → файл сохранил смысл"
else
    bad "круг изменил конфигурацию"
    diff "$WORK/n1" "$WORK/n2" | sed 's/^/        /' || true
fi
if "$GO" check - < "$WORK/a.link" >/dev/null 2>&1; then ok "check принимает ссылку со ввода"
else bad "check не принял ссылку"; fi

# ---- 2. живой туннель по ссылке ----------------------------------------------
for ns in $NSH $NSA; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add ha netns $NSH type veth peer name ah netns $NSA
ip -n $NSH addr add 10.212.1.1/24 dev ha
ip -n $NSA addr add 10.212.1.2/24 dev ah
ip -n $NSH link set ha up; ip -n $NSA link set ah up

ip netns exec $NSH "$GO" hub "$WORK/hub.conf" > "$WORK/hub.log" 2>&1 &
sleep 0.8
# ССЫЛКА ИДЁТ СО СТАНДАРТНОГО ВВОДА, а не аргументом, и это тот самый способ, ради которого «-»
# существует: аргументы команды видны в списке процессов всякому на машине.
ip netns exec $NSA "$GO" up - --dev xsl0 < "$WORK/a.link" > "$WORK/a.log" 2>&1 &

up=0
for i in $(seq 1 80); do
    grep -q 'поднялся' "$WORK/hub.log" 2>/dev/null && { up=1; break; }
    sleep 0.25
done
if [ "$up" = 1 ]; then ok "хаб опознал пира, поднятого по ссылке"
else bad "туннель по ссылке не поднялся"; sed 's/^/        /' "$WORK/a.log" | tail -6; fi

if ip netns exec $NSA ping -c 3 -W 2 -q 10.79.0.1 >/dev/null 2>&1; then
    ok "туннель по ссылке несёт трафик"
else
    bad "ping через туннель по ссылке не прошёл"
fi
if ip netns exec $NSA ip link show xsl0 >/dev/null 2>&1; then ok "устройство из ссылки поднято"
else bad "устройства нет"; fi

echo
[ "$fails" = 0 ] && echo "ссылка xs:// сошлась целиком" || echo "провалов: $fails"
exit $fails
