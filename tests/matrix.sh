#!/bin/sh
# Матрица совместимости: обе реализации хаба против обеих реализаций клиента.
#
# ЗАЧЕМ ИМЕННО МАТРИЦА. У протокола две половины и две реализации, то есть четыре сочетания, и
# каждое из них кто-то будет использовать: роутер к серверу на C, десктоп к тому же серверу, десктоп
# к серверу на Go, роутер к серверу на Go. Проверять «свою против своей» бессмысленно — так
# проверяется согласованность реализации с самой собой, а не формат на проводе. Расхождение видно
# только в перекрёстных клетках, и именно они здесь и гоняются.
#
# ФОРМАТ У ОБЕИХ РЕАЛИЗАЦИЙ ОДИН. Пачки кадров, разрезание записей между сегментами и
# ClientHello браузерного размера перенесены в движок на C, поэтому перекрёстные клетки гоняются
# в обычном режиме — именно они и доказывают, что перенос сделан верно, а не «собралось».
#
# XSM_COMPAT=1 прогоняет перекрёстные клетки со старым форматом (--no-batch у половины на Go):
# так проверяется, что запасной путь на месте — он нужен, пока где-то живёт хаб предыдущей
# версии.
#
# Каждая клетка — отдельные пространства имён, свои ключи, полный подъём с нуля.
#
#     sudo sh tests/matrix.sh            все четыре клетки
#     sudo sh tests/matrix.sh go c       только хаб на Go против клиента на C
set -eu
umask 077

HUB_C=${STEER_HUB_BIN:-../steer/build/steer-hub}
CLI_C=${STEER_EXT_BIN:-../steer/build/steer-ext}
GO=${XSTEER_BIN:-./build/xsteer}
NSH=xsm-hub
NSA=xsm-a
NSB=xsm-b
WORK=
fails=0

ok()  { printf '    %-52s ok\n' "$1"; }
bad() { printf '    %-52s ПРОВАЛ\n' "$1"; fails=$((fails + 1)); }

cleanup() {
    for ns in $NSH $NSA $NSB; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    [ -n "$WORK" ] && [ -z "${XSM_KEEP:-}" ] && rm -rf "$WORK"
    return 0
}
# PIPE обязателен: вывод стенда читают через конвейер, и без этого сигнала в trap оболочка гибнет
# до уборки, оставляя в системе клиенты, которые портят любой следующий замер.
trap cleanup EXIT INT TERM PIPE HUP

[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 2; }
[ -c /dev/net/tun ] || { echo "нет /dev/net/tun"; exit 2; }
[ -x "$GO" ] || { echo "нет $GO — соберите: go build -o build/xsteer ./cmd/xsteer"; exit 2; }

have_c_hub=1; [ -x "$HUB_C" ] || have_c_hub=0
have_c_cli=1; [ -x "$CLI_C" ] || have_c_cli=0

# Одна клетка матрицы: $1 — хаб (c|go), $2 — клиент (c|go).
cell() {
    hub_kind="$1"; cli_kind="$2"
    printf '\n== хаб %s ← клиент %s ==\n' "$hub_kind" "$cli_kind"
    cleanup
    WORK="$(mktemp -d)"; chmod 700 "$WORK"

    for ns in $NSH $NSA $NSB; do ip netns add $ns; ip -n $ns link set lo up; done
    # Пересылку в ядре выключаем ЯВНО: связь пир↔пир обязана работать без неё — трафик
    # разворачивает сам хаб в пользовательском пространстве. Значение наследуется от хозяйской
    # системы, и на машине с включённой пересылкой стенд проверял бы не то, что обещает.
    for ns in $NSH $NSA $NSB; do ip netns exec $ns sysctl -qw net.ipv4.ip_forward=0; done
    ip link add ha netns $NSH type veth peer name ah netns $NSA
    ip link add hb netns $NSH type veth peer name bh netns $NSB
    ip -n $NSH addr add 10.212.1.1/24 dev ha
    ip -n $NSA addr add 10.212.1.2/24 dev ah
    ip -n $NSH addr add 10.212.2.1/24 dev hb
    ip -n $NSB addr add 10.212.2.2/24 dev bh
    for p in "$NSH ha" "$NSA ah" "$NSH hb" "$NSB bh"; do set -- $p; ip -n "$1" link set "$2" up; done

    priv_hub=$("$GO" genkey); pub_hub=$(printf '%s\n' "$priv_hub" | "$GO" pubkey)
    priv_a=$("$GO" genkey);   pub_a=$(printf '%s\n' "$priv_a" | "$GO" pubkey)
    priv_b=$("$GO" genkey);   pub_b=$(printf '%s\n' "$priv_b" | "$GO" pubkey)

    cat > "$WORK/hub.conf" <<EOF
[Interface]
PrivateKey = $priv_hub
Address    = 10.79.0.1/24
ListenPort = 443

[Peer]
PublicKey  = $pub_a
AllowedIPs = 10.79.0.2/32

[Peer]
PublicKey  = $pub_b
AllowedIPs = 10.79.0.3/32
EOF
    for pair in "a $priv_a 10.79.0.2 10.212.1.1" "b $priv_b 10.79.0.3 10.212.2.1"; do
        set -- $pair
        cat > "$WORK/$1.conf" <<EOF
[Interface]
PrivateKey = $2
Address    = $3/24
SNI        = www.microsoft.com

[Peer]
PublicKey  = $pub_hub
AllowedIPs = 10.79.0.0/24
Endpoint   = $4:443
PersistentKeepalive = 15
EOF
        # Спека нужна клиенту на C: устройство и выход он берёт оттуда. Каналов в ней нет — стенд
        # проверяет туннель, а не маршрутизацию по правилам.
        cat > "$WORK/$1.json" <<EOF
{"schema":1,"lan_device":"lo","from_default":["10.79.0.0/24"],
 "outputs":{"vpn$1":{"kind":"xsteer","conf":"$WORK/$1.conf"}},
 "channels":[]}
EOF
    done
    chmod 600 "$WORK"/*.conf
    mkdir -p "$WORK/state"

    # Перепроверка пути раз в три секунды: стенду надо увидеть работу согласования.
    export STEER_XS_PROBE_MS=3000

    # Старый формат — только по прямой просьбе: обе реализации давно говорят на новом.
    compat=""
    if [ -n "${XSM_COMPAT:-}" ] && { [ "$hub_kind" = c ] || [ "$cli_kind" = c ]; }; then
        compat="--no-batch"
    fi

    if [ "$hub_kind" = c ]; then
        ip netns exec $NSH "$HUB_C" xsteer-hub --config "$WORK/hub.conf" \
            --state-dir "$WORK/state" > "$WORK/hub.log" 2>&1 &
    else
        ip netns exec $NSH "$GO" hub "$WORK/hub.conf" $compat > "$WORK/hub.log" 2>&1 &
    fi
    sleep 0.8

    if [ "$cli_kind" = c ]; then
        deva=vpna; devb=vpnb
        ip netns exec $NSA "$CLI_C" xsteer vpna --spec "$WORK/a.json" \
            --state-dir "$WORK/state" > "$WORK/a.log" 2>&1 &
        ip netns exec $NSB "$CLI_C" xsteer vpnb --spec "$WORK/b.json" \
            --state-dir "$WORK/state" > "$WORK/b.log" 2>&1 &
    else
        deva=xsa; devb=xsb
        ip netns exec $NSA "$GO" up "$WORK/a.conf" --dev xsa --probe-ms 3000 $compat \
            > "$WORK/a.log" 2>&1 &
        ip netns exec $NSB "$GO" up "$WORK/b.conf" --dev xsb --probe-ms 3000 $compat \
            > "$WORK/b.log" 2>&1 &
    fi

    # Считаются РАЗНЫЕ пиры, а не строки: клиент открывает по соединению на ядро, и строк
    # «поднялся» у него столько же. Проверять число строк значило бы вписать в стенд число ядер
    # машины, на которой он запущен.
    count_up() { grep -h 'поднялся' "$WORK/hub.log" 2>/dev/null \
                 | sed 's/.*пир \([^ ]*\) .*/\1/' | sort -u | grep -c . || true; }
    for i in $(seq 1 100); do [ "$(count_up)" -ge 2 ] && break; sleep 0.25; done
    peers=$(count_up)
    if [ "$peers" -ge 2 ]; then
        ok "рукопожатие: хаб опознал оба клиента"
    else
        bad "рукопожатие: хаб опознал оба клиента (опознано $peers)"
        echo "    --- журнал хаба ---";     sed 's/^/    /' "$WORK/hub.log" | tail -12
        echo "    --- журнал клиента A ---"; sed 's/^/    /' "$WORK/a.log" | tail -12
        return 0
    fi

    if ip netns exec $NSA ping -c 3 -W 2 -q 10.79.0.1 >/dev/null 2>&1; then
        ok "клиент A → хаб: ping"
    else
        bad "клиент A → хаб: ping"; sed 's/^/    /' "$WORK/a.log" | tail -8
    fi
    if ip netns exec $NSA ping -c 3 -W 2 -q 10.79.0.3 >/dev/null 2>&1; then
        ok "клиент A → клиент B через хаб: ping"
    else
        bad "клиент A → клиент B через хаб: ping"; sed 's/^/    /' "$WORK/hub.log" | tail -8
    fi

    # Согласование MTU: число НЕ зашито — его выясняют сами стороны.
    mtu_of() { ip netns exec $NSA cat "/sys/class/net/$deva/mtu" 2>/dev/null || echo 0; }
    _last=""; _same=0; _i=0
    while [ $_same -lt 6 ] && [ $_i -lt 100 ]; do
        _cur=$(mtu_of)
        if [ "$_cur" = "$_last" ]; then _same=$((_same + 1)); else _same=0; _last=$_cur; fi
        sleep 0.5; _i=$((_i + 1))
    done
    link=$(ip netns exec $NSA cat /sys/class/net/ah/mtu)
    if [ "$_last" = "$((link - 61))" ]; then
        ok "MTU туннеля согласован: $_last при канале $link"
    else
        bad "MTU туннеля согласован (хочу $((link - 61)), есть $_last)"
    fi

    if command -v iperf3 >/dev/null; then
        ip netns exec $NSH iperf3 -s -D -B 10.79.0.1 --logfile "$WORK/is.log" 2>/dev/null || true
        sleep 0.4
        sp=$(ip netns exec $NSA iperf3 -c 10.79.0.1 -t 4 -P 4 -J 2>/dev/null \
             | awk '/sum_sent/,/}/' | awk -F'[:,]' '/bits_per_second/ {printf "%.0f", $2/1000000; exit}')
        [ -n "$sp" ] && ok "iperf3, четыре потока: ${sp} Мбит/с" || bad "iperf3 не измерился"
    fi
}

want_hub="${1:-both}"; want_cli="${2:-both}"
for hk in c go; do
    [ "$want_hub" = both ] || [ "$want_hub" = "$hk" ] || continue
    [ "$hk" = c ] && [ "$have_c_hub" = 0 ] && { echo "== хаб c пропущен: нет $HUB_C"; continue; }
    for ck in c go; do
        [ "$want_cli" = both ] || [ "$want_cli" = "$ck" ] || continue
        [ "$ck" = c ] && [ "$have_c_cli" = 0 ] && { echo "== клиент c пропущен: нет $CLI_C"; continue; }
        cell "$hk" "$ck"
    done
done

echo
if [ "$fails" -gt 0 ]; then echo "ЕСТЬ ПРОВАЛЫ: $fails"; exit 1; fi
echo "матрица совместимости сошлась целиком"
