#!/bin/sh
# Поддельный TCP против настоящего потока — на канале с потерями.
#
# ЗАЧЕМ. На Windows поддельный TCP невозможен без драйвера-перехватчика, и есть выбор: тащить
# драйвер (WinDivert: трение с антивирусами, лицензия, подпись) или вести записи по настоящему
# сокету. Второе бесплатно улучшает облик — настоящий стек сам делает всё, что мы изображали
# руками, — но означает TCP внутри TCP, ровно то, от чего протокол уходил.
#
# Спорить об этом бессмысленно: вопрос решается числами. Стенд гоняет ОДНУ и ту же нагрузку через
# оба транспорта при потерях 0, 1 и 3 процента и печатает таблицу.
#
# Потери ставятся правилом на ВХОДЕ каждой стороны и только по внешнему порту: внутренний трафик
# идёт через устройство туннеля и под правило не попадает — иначе потери считались бы дважды.
#
#     sudo sh tests/loss.sh [секунд_на_замер]
set -eu
umask 077

SECS="${1:-6}"
GO=${XSTEER_BIN:-./build/xsteer}
NSH=xl-hub
NSA=xl-a
FAKE_PORT=443
STREAM_PORT=8443
WORK=

# Уборка пространств имён — отдельно от уборки рабочего каталога: она зовётся МЕЖДУ клетками, а
# каталог с ключами и журналами должен жить до конца прогона. Первая версия сносила его в начале
# каждой клетки, и все шесть клеток печатали «не поднялся».
teardown_ns() {
    for ns in $NSH $NSA; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    return 0
}

cleanup() {
    teardown_ns
    [ -n "$WORK" ] && [ -z "${XL_KEEP:-}" ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT INT TERM PIPE HUP
cleanup

[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 2; }
[ -c /dev/net/tun ] || { echo "нет /dev/net/tun"; exit 2; }
[ -x "$GO" ] || { echo "нет $GO"; exit 2; }
command -v iperf3 >/dev/null || { echo "нет iperf3"; exit 2; }

WORK="$(mktemp -d)"; chmod 700 "$WORK"
priv_h=$("$GO" genkey); pub_h=$(printf '%s\n' "$priv_h" | "$GO" pubkey)
priv_a=$("$GO" genkey); pub_a=$(printf '%s\n' "$priv_a" | "$GO" pubkey)
cat > "$WORK/hub.conf" <<EOF
[Interface]
PrivateKey = $priv_h
Address    = 10.84.0.1/24
ListenPort = $FAKE_PORT

[Peer]
PublicKey  = $pub_a
AllowedIPs = 10.84.0.2/32
EOF
cat > "$WORK/a.conf" <<EOF
[Interface]
PrivateKey = $priv_a
Address    = 10.84.0.2/24
SNI        = www.microsoft.com

[Peer]
PublicKey  = $pub_h
AllowedIPs = 10.84.0.0/24
Endpoint   = 10.217.1.1:$FAKE_PORT
PersistentKeepalive = 15
EOF
chmod 600 "$WORK"/*.conf

# $1 — транспорт (fake|stream), $2 — потери в процентах. Печатает «один_поток четыре_потока».
run_case() {
    tr="$1"; loss="$2"
    teardown_ns
    for ns in $NSH $NSA; do ip netns add $ns; ip -n $ns link set lo up; done
    ip link add ha netns $NSH type veth peer name ah netns $NSA
    ip -n $NSH addr add 10.217.1.1/24 dev ha
    ip -n $NSA addr add 10.217.1.2/24 dev ah
    ip -n $NSH link set ha up; ip -n $NSA link set ah up
    # Разгрузку выключаем: с ней ядро отдаёт в veth суперпакеты, и «процент потерянных пакетов»
    # означал бы совсем другую долю потерянных сегментов у одного транспорта и у другого.
    for p in "$NSH ha" "$NSA ah"; do
        set -- $p
        ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1 || true
    done

    port=$FAKE_PORT
    [ "$tr" = stream ] && port=$STREAM_PORT
    if [ "$loss" != 0 ]; then
        # Потери по внешнему порту и только по нему: внутренний трафик идёт через устройство
        # туннеля, и попади он под то же правило — потери считались бы дважды.
        ip netns exec $NSH nft add table inet losstest
        ip netns exec $NSH nft add chain inet losstest c '{ type filter hook input priority -300 ; }'
        ip netns exec $NSH nft add rule inet losstest c tcp dport $port \
            numgen random mod 100 lt "$loss" counter drop
        ip netns exec $NSA nft add table inet losstest
        ip netns exec $NSA nft add chain inet losstest c '{ type filter hook input priority -300 ; }'
        ip netns exec $NSA nft add rule inet losstest c tcp sport $port \
            numgen random mod 100 lt "$loss" counter drop
    fi

    if [ "$tr" = stream ]; then
        ip netns exec $NSH "$GO" hub "$WORK/hub.conf" --stream-port $STREAM_PORT \
            > "$WORK/hub-$tr-$loss.log" 2>&1 &
        sleep 1.2
        ip netns exec $NSA "$GO" up "$WORK/a.conf" --dev xsa --stream-port $STREAM_PORT \
            > "$WORK/a-$tr-$loss.log" 2>&1 &
    else
        ip netns exec $NSH "$GO" hub "$WORK/hub.conf" > "$WORK/hub-$tr-$loss.log" 2>&1 &
        sleep 1.2
        ip netns exec $NSA "$GO" up "$WORK/a.conf" --dev xsa --probe-ms 3000 \
            > "$WORK/a-$tr-$loss.log" 2>&1 &
    fi
    for i in $(seq 1 80); do grep -q 'поднялся' "$WORK/hub-$tr-$loss.log" 2>/dev/null && break; sleep 0.25; done
    if ! grep -q 'поднялся' "$WORK/hub-$tr-$loss.log" 2>/dev/null; then
        echo "не поднялся"
        return 0
    fi
    # Дать согласованию MTU устояться: замер на переезжающем MTU относится к переезду.
    sleep 4

    ip netns exec $NSH iperf3 -s -D -B 10.84.0.1 --logfile "$WORK/is.log" 2>/dev/null || true
    sleep 0.5
    # Оба направления, и это не полнота ради полноты: вверх отправляет стек КЛИЕНТА (на Windows —
    # виндовый), вниз — стек хаба (Linux, здесь с BBR). Загрузка у людей чаще идёт вниз, и цена
    # TCP-в-TCP в этих направлениях разная.
    speed() {   # $1 — потоков, $2 — «-R» для загрузки вниз
        ip netns exec $NSA iperf3 -c 10.84.0.1 -t "$SECS" -P "$1" $2 -J 2>/dev/null \
            | awk '/sum_received/,/}/' \
            | awk -F'[:,]' '/bits_per_second/ {printf "%.0f", $2/1000000; exit}'
    }
    up=$(speed 1 ""); down=$(speed 1 "-R"); down4=$(speed 4 "-R")
    echo "${up:-—} ${down:-—} ${down4:-—}"
}

printf '\n%-11s %7s %13s %14s %16s\n' транспорт потери "вверх, 1" "вниз, 1" "вниз, 4"
for tr in fake stream; do
    for loss in 0 1 3; do
        out=$(run_case "$tr" "$loss")
        set -- $out
        name="поддельный"; [ "$tr" = stream ] && name="поток"
        printf '%-11s %6s%% %6s Мбит/с %7s Мбит/с %9s Мбит/с\n' \
               "$name" "$loss" "${1:-—}" "${2:-—}" "${3:-—}"
    done
done
echo
echo "Числа — принятое приложением (goodput) через туннель. Потери ставятся по внешнему порту в обе"
echo "стороны, то есть теряются сегменты транспорта, а не пакеты приложения. Управление перегрузкой"
echo "в пространствах имён — то же, что на машине:"
sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null | sed 's/^/    /'

