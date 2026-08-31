#!/bin/sh
# Замер скорости туннеля с разгрузкой сегментации и без неё — в одном прогоне и на одном стенде.
#
# ЗАЧЕМ А/Б, А НЕ ПРОСТО ЗАМЕР. Числа туннеля разнятся между прогонами на десятки процентов: трафик
# раскладывается по соединениям хешем потока, и на малом числе потоков раскладка бывает неровной.
# Поэтому «стало быстрее» доказывается только сравнением двух прогонов подряд, на одной машине, в
# одних пространствах имён и на том же числе потоков. Одиночное число здесь ничего не значит.
#
#     sudo sh tests/speed.sh              шестнадцать потоков, оба направления
#     sudo sh tests/speed.sh 4            четыре потока
#
# ПОЧЕМУ ШЕСТНАДЦАТЬ ПО УМОЛЧАНИЮ. На четырёх ядро иногда сваливает все потоки в одну очередь
# устройства, то есть в одно соединение и одно ядро, и замер показывает раскладку, а не туннель.
set -eu
umask 077

GO=${XSTEER_BIN:-./build/xsteer}
STREAMS=${1:-16}
SECS=${XSS_SECS:-6}
NSH=xss-hub
NSA=xss-a
WORK=

cleanup() {
    for ns in $NSH $NSA; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    [ -n "$WORK" ] && [ -z "${XSS_KEEP:-}" ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT INT TERM PIPE HUP

[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 2; }
[ -c /dev/net/tun ] || { echo "нет /dev/net/tun"; exit 2; }
[ -x "$GO" ] || { echo "нет $GO — соберите: go build -o build/xsteer ./cmd/xsteer"; exit 2; }
command -v iperf3 >/dev/null || { echo "нет iperf3"; exit 2; }

# mbps вытаскивает скорость из отчёта iperf3 в формате JSON: сумма по всем потокам.
mbps() {
    python3 - "$1" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(int(d["end"]["sum_received"]["bits_per_second"] / 1e6))
except Exception:
    print(0)
PY
}

# run — один прогон: поднять всё, померить, снять. $1 — ключи движка ("" или --no-offload).
run() {
    extra="$1"
    cleanup
    WORK="$(mktemp -d)"; chmod 700 "$WORK"
    for ns in $NSH $NSA; do ip netns add $ns; ip -n $ns link set lo up; done
    ip link add ha netns $NSH type veth peer name ah netns $NSA
    ip -n $NSH addr add 10.212.1.1/24 dev ha
    ip -n $NSA addr add 10.212.1.2/24 dev ah
    ip -n $NSH link set ha up; ip -n $NSA link set ah up

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

    ip netns exec $NSH "$GO" hub "$WORK/hub.conf" $extra > "$WORK/hub.log" 2>&1 &
    sleep 0.8
    ip netns exec $NSA "$GO" up "$WORK/a.conf" --dev xsa $extra > "$WORK/a.log" 2>&1 &

    for i in $(seq 1 80); do
        grep -q 'поднялся' "$WORK/hub.log" 2>/dev/null && break
        sleep 0.25
    done
    if ! grep -q 'поднялся' "$WORK/hub.log" 2>/dev/null; then
        echo "  туннель не поднялся:"; sed 's/^/    /' "$WORK/hub.log" | tail -8; return 1
    fi
    # Ждём, пока согласование MTU устоится: замер на съезжающем MTU меряет согласование.
    sleep 3

    grep -h 'разгрузка сегментации' "$WORK/a.log" | head -1 | sed 's/^/  клиент: /'
    grep -h 'разгрузка сегментации' "$WORK/hub.log" | head -1 | sed 's/^/  хаб:    /'

    ip netns exec $NSH iperf3 -s -D -B 10.79.0.1 --logfile "$WORK/is.log" 2>/dev/null || true
    sleep 0.5
    ip netns exec $NSA iperf3 -c 10.79.0.1 -P "$STREAMS" -t "$SECS" -J > "$WORK/up.json" 2>/dev/null || true
    ip netns exec $NSA iperf3 -c 10.79.0.1 -P "$STREAMS" -t "$SECS" -R -J > "$WORK/dn.json" 2>/dev/null || true
    up=$(mbps "$WORK/up.json"); dn=$(mbps "$WORK/dn.json")
    printf '  клиент → хаб: %6s Мбит/с      хаб → клиент: %6s Мбит/с\n' "$up" "$dn"
}

echo "стенд: $(uname -m), $(nproc) ядер, $STREAMS потоков, $SECS с на направление"
echo
echo "== с разгрузкой сегментации =="
run ""
echo
echo "== без разгрузки (--no-offload) =="
run "--no-offload"
