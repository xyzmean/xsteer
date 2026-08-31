#!/bin/sh
# Восстановление туннеля: падение канала, возврат канала, смена адреса.
#
# ЗАЧЕМ СТЕНД, А НЕ РАССУЖДЕНИЕ. Всё, что здесь чинится, — это СРОКИ, а срок либо измерен, либо
# выдуман. Проверяются три случая, и каждый из них раньше стоил десятков секунд:
#
#   1. канал упал и вернулся      — сколько молчит туннель после возврата;
#   2. адрес выхода сменился      — сколько молчит туннель, когда сеть та же, а адрес другой;
#   3. пир вернулся с новой точки — сколько хаб держит слот, ведущий в точку, которой больше нет.
#
#     sudo sh tests/roam.sh
set -eu
umask 077

GO=${XSTEER_BIN:-./build/xsteer}
NSH=xsr-hub
NSA=xsr-a
WORK=
fails=0

ok()  { printf '    %-56s ok  (%s)\n' "$1" "$2"; }
bad() { printf '    %-56s ПРОВАЛ (%s)\n' "$1" "$2"; fails=$((fails + 1)); }

cleanup() {
    for ns in $NSH $NSA; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    [ -n "$WORK" ] && [ -z "${XSR_KEEP:-}" ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT INT TERM PIPE HUP

[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 2; }
[ -c /dev/net/tun ] || { echo "нет /dev/net/tun"; exit 2; }
[ -x "$GO" ] || { echo "нет $GO — соберите: go build -o build/xsteer ./cmd/xsteer"; exit 2; }

# ms — монотонные миллисекунды.
ms() { python3 -c 'import time;print(int(time.monotonic()*1000))'; }

# wait_ping — сколько миллисекунд прошло, пока туннель снова не понёс трафик. Печатает число или
# "не дождался".
wait_ping() {
    limit=$1
    t0=$(ms)
    while [ $(( $(ms) - t0 )) -lt "$limit" ]; do
        if ip netns exec $NSA ping -c 1 -W 1 -q 10.79.0.1 >/dev/null 2>&1; then
            echo $(( $(ms) - t0 )); return 0
        fi
    done
    echo "не дождался"; return 1
}

WORK="$(mktemp -d)"; chmod 700 "$WORK"
for ns in $NSH $NSA; do ip netns add $ns; ip -n $ns link set lo up; done
# ДВА пути, а не один, и это не украшение стенда. Смена сети — это когда трафик к тому же хабу
# начинает уходить через другой интерфейс и с другого адреса источника (Wi-Fi на мобильную и
# обратно). Проверять её сменой адреса на одном интерфейсе нельзя: Linux при удалении основного
# адреса удаляет и все дополнительные из той же сети, и вместо переезда выходит «сети нет вовсе» —
# то есть проверялся бы уже проверенный случай 1.
ip link add ha1 netns $NSH type veth peer name ah1 netns $NSA
ip link add ha2 netns $NSH type veth peer name ah2 netns $NSA
ip -n $NSH addr add 10.212.1.1/24 dev ha1
ip -n $NSA addr add 10.212.1.2/24 dev ah1
ip -n $NSH addr add 10.212.2.1/24 dev ha2
ip -n $NSA addr add 10.212.2.2/24 dev ah2
for p in "$NSH ha1" "$NSA ah1" "$NSH ha2" "$NSA ah2"; do set -- $p; ip -n "$1" link set "$2" up; done
# Хаб отвечает на свой адрес 10.212.1.1, приехавший по ЛЮБОМУ из путей: так и ведёт себя обычный
# Linux, и именно поэтому пиру не приходится менять Endpoint при переезде.
ip netns exec $NSA sysctl -qw net.ipv4.conf.all.rp_filter=0 || true
ip netns exec $NSH sysctl -qw net.ipv4.conf.all.rp_filter=0 || true

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

ip netns exec $NSH "$GO" hub "$WORK/hub.conf" > "$WORK/hub.log" 2>&1 &
sleep 0.8
ip netns exec $NSA "$GO" up "$WORK/a.conf" --dev xsa > "$WORK/a.log" 2>&1 &

for i in $(seq 1 80); do grep -q 'поднялся' "$WORK/hub.log" 2>/dev/null && break; sleep 0.25; done
if ! grep -q 'поднялся' "$WORK/hub.log" 2>/dev/null; then
    echo "туннель не поднялся:"; sed 's/^/    /' "$WORK/hub.log" | tail -10; exit 1
fi
if ! t=$(wait_ping 5000); then echo "туннель не понёс трафик"; exit 1; fi
printf '\n== туннель поднят (%s мс до первого ответа) ==\n\n' "$t"

# ---- 1. канал упал и вернулся ------------------------------------------------
#
# Пять секунд простоя — это заметно больше, чем нужно, чтобы прежний код успел объявить путь мёртвым
# по своему сроку. То есть проверяется именно возврат, а не то, что туннель ничего не заметил.
echo "1. канал упал на 5 с и вернулся"
ip netns exec $NSA ip link set ah1 down
sleep 5
ip netns exec $NSA ip link set ah1 up
ip netns exec $NSA ip addr replace 10.212.1.2/24 dev ah1
if t=$(wait_ping 60000); then
    if [ "$t" -le 5000 ]; then ok "туннель вернулся" "${t} мс"; else bad "туннель вернулся слишком долго" "${t} мс"; fi
else
    bad "туннель не вернулся" "60 с"
fi

# ---- 2. сменился адрес выхода ------------------------------------------------
#
# Хаб тот же и Endpoint тот же, а путь и адрес источника другие. Для ПОДКЛЮЧЁННОГО сырого сокета это
# конец: адрес источника закреплён при открытии. Прежде выяснялось это только тишиной.
echo "2. трафик к хабу ушёл через другой интерфейс (10.212.1.2 → 10.212.2.2)"
ip netns exec $NSA ip route replace 10.212.1.1/32 via 10.212.2.1 dev ah2
ip netns exec $NSA ip link set ah1 down
if t=$(wait_ping 60000); then
    if [ "$t" -le 5000 ]; then ok "туннель переехал на другой путь" "${t} мс"; else bad "переезд слишком долгий" "${t} мс"; fi
else
    bad "туннель не переехал" "60 с"
fi

# ---- 3. пир вернулся МЕНЬШИМ числом соединений -------------------------------
#
# Случай, который не закрывается сам собой. Пока пир переподключает все свои соединения, каждое из
# них занимает СВОЙ слот в наборе, и прежняя запись в этом слоте вытесняется сразу. А вот слоты,
# которые пир больше не занимает (стало меньше ядер, другая настройка, другая сборка), остаются
# указывать на точку, которой нет. Получателя хаб выбирает хешем потока среди живых слотов, поэтому
# такой слот — не задержка, а потеря доли потоков ЦЕЛИКОМ, и раньше он жил до IdleMS, то есть три
# минуты.
#
# Проверяется именно это: клиент возвращается с одним соединением вместо всех, и хаб обязан снять
# осиротевшие слоты пробой — за полсекунды, а не за три минуты.
echo "3. пир вернулся одним соединением вместо всех"
ip netns pids $NSA 2>/dev/null | xargs -r kill 2>/dev/null || true
sleep 0.5
: > "$WORK/a2.log"
ip netns exec $NSA "$GO" up "$WORK/a.conf" --dev xsa --conns 1 > "$WORK/a2.log" 2>&1 &
t0=$(ms)
got=0
while [ $(( $(ms) - t0 )) -lt 15000 ]; do
    if grep -q 'не ответила на пробу — снимаю её слот сразу' "$WORK/hub.log"; then got=1; break; fi
    sleep 0.1
done
dt=$(( $(ms) - t0 ))
if [ "$got" = 1 ]; then
    n=$(grep -c 'не ответила на пробу' "$WORK/hub.log")
    if [ "$dt" -le 5000 ]; then ok "осиротевшие слоты сняты пробой ($n шт.)" "${dt} мс"
    else bad "слоты сняты, но слишком поздно ($n шт.)" "${dt} мс"; fi
else
    bad "осиротевшие слоты не сняты" "15 с; см. $WORK/hub.log"
fi
if t=$(wait_ping 15000); then ok "туннель работает одним соединением" "${t} мс"
else bad "туннель не работает после возврата одним соединением" "15 с"; fi

echo
echo "--- что увидел клиент ---"
grep -E 'сеть:|поднимаю заново|путь наружу|путь молчит' "$WORK/a.log" | tail -8 | sed 's/^/    /'
echo
[ "$fails" = 0 ] && echo "восстановление сошлось целиком" || echo "провалов: $fails"
exit $fails
