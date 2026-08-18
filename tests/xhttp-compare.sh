#!/bin/sh
# Сравнение формы трафика: xsteer против настоящего xhttp (Xray).
#
# ЗАЧЕМ. «Похоже на TLS» — это утверждение о наблюдаемом, и проверять его надо наблюдением. Стенд
# поднимает ДВА туннеля в одинаковой обстановке (те же пространства имён, тот же veth, та же
# нагрузка), записывает провод с ПЕРВОГО пакета и считает по обеим записям одни и те же признаки.
# Всё, где числа расходятся, — это то, по чему нас можно отличить.
#
# Xray нужен настоящий: подделать эталон, с которым сравниваешься, значит сравниться с собой.
#
#     sudo XRAY_BIN=/path/to/xray sh tests/xhttp-compare.sh [мегабайт]
set -eu
umask 077

MB="${1:-8}"
# Скорость передачи. По умолчанию 100 Мбит/с, и это не осторожность: на предельной скорости
# (полтора гигабита в пространствах имён) форма потока другая, чем на любом настоящем канале, —
# ядро отдаёт пакеты плотнее, чем это бывает у пользователя, и часть признаков (соотношение
# голых подтверждений, паузы) относится к обстановке, а не к протоколу. Сравнивать надо на той
# скорости, на которой протокол работает у людей.
RATE="${RATE:-12M}"
GO=${XSTEER_BIN:-./build/xsteer}
# XS_IMPL=c снимает запись с реализации на C (движок steer) вместо реализации на Go. Нужно ровно
# для одного: убедиться, что перенос формата в C дал ТУ ЖЕ форму на проводе, а не только
# совместимость. «Собралось и соединилось» и «выглядит так же» — разные утверждения.
XS_IMPL="${XS_IMPL:-go}"
# XS_STREAM=1 снимает запись с режима ПОТОКА (записи по настоящему TCP). Нужно, чтобы проверить
# утверждение «в потоке облик лучше» — а не поверить ему.
XS_STREAM="${XS_STREAM:-}"
C_HUB=${STEER_HUB_BIN:-../steer/build/steer-hub}
C_EXT=${STEER_EXT_BIN:-../steer/build/steer-ext}
XRAY=${XRAY_BIN:-}
IDLE="${IDLE:-25}"     # сколько молчать после передачи: за это время видно keepalive
NSC=xc-cli
NSS=xc-srv
WORK=

cleanup() {
    pkill -x tcpdump 2>/dev/null || true
    for ns in $NSC $NSS; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    [ -n "$WORK" ] && [ -z "${XC_KEEP:-}" ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT INT TERM PIPE HUP
cleanup

[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 2; }
[ -x "$GO" ] || { echo "нет $GO"; exit 2; }
[ -n "$XRAY" ] && [ -x "$XRAY" ] || { echo "нужен настоящий Xray: XRAY_BIN=/путь/к/xray"; exit 2; }
command -v tcpdump >/dev/null || { echo "нет tcpdump"; exit 2; }

WORK="$(mktemp -d)"; chmod 700 "$WORK"
for ns in $NSC $NSS; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add cs netns $NSC type veth peer name sc netns $NSS
ip -n $NSC addr add 10.216.1.2/24 dev cs
ip -n $NSS addr add 10.216.1.1/24 dev sc
ip -n $NSC link set cs up; ip -n $NSS link set sc up
# РАЗГРУЗКУ ВЫКЛЮЧАЕМ, и без этого сравнение недействительно.
#
# С включённой сегментацией на устройстве ядро отдаёт в veth «суперпакеты» по 8-64 КБ, и tcpdump
# записывает именно их: у настоящего xhttp в записи появляются сегменты по 8223 байта, которых на
# проводе не бывает. Наши же пакеты идут из сырого сокета готовыми по 1460 — и сравнение
# «границы записей против границ сегментов», то есть главный признак, сравнивало бы разное с
# разным. Выключив разгрузку, мы видим у обоих ту сегментацию, которая будет на настоящем канале.
for pair in "$NSC cs" "$NSS sc"; do
    set -- $pair
    ip netns exec "$1" ethtool -K "$2" tso off gso off gro off tx off sg off >/dev/null 2>&1 || true
done

mkdir -p "$WORK/www"
head -c $((MB * 1024 * 1024)) /dev/urandom > "$WORK/www/blob.bin"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
    -days 2 -subj "/CN=decoy.example.net" >/dev/null 2>&1
PIN=$(openssl x509 -in "$WORK/c.pem" -outform der | openssl dgst -sha256 -hex | sed 's/.*= *//')
UUID=$(cat /proc/sys/kernel/random/uuid)

# ---- 1. настоящий xhttp -----------------------------------------------------
cat > "$WORK/srv.json" <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"10.216.1.1","port":8443,"protocol":"vless",
   "settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},
   "streamSettings":{"network":"xhttp","security":"tls",
     "tlsSettings":{"certificates":[{"certificateFile":"$WORK/c.pem","keyFile":"$WORK/k.pem"}]},
     "xhttpSettings":{"path":"/tunnel","mode":"auto"}}}],
 "outbounds":[{"protocol":"freedom"}]}
EOF
cat > "$WORK/cli.json" <<EOF
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":1080,"protocol":"socks","settings":{"udp":false}}],
 "outbounds":[{"protocol":"vless",
   "settings":{"vnext":[{"address":"10.216.1.1","port":8443,
     "users":[{"id":"$UUID","encryption":"none"}]}]},
   "streamSettings":{"network":"xhttp","security":"tls",
     "tlsSettings":{"serverName":"decoy.example.net","pinnedPeerCertSha256":"$PIN"},
     "xhttpSettings":{"path":"/tunnel","mode":"auto"}}}]}
EOF
ip netns exec $NSS python3 -m http.server 8080 --bind 10.216.1.1 --directory "$WORK/www" \
    > "$WORK/httpd.log" 2>&1 &
sleep 0.5
# Запись начинается ДО подъёма туннеля: рукопожатие — половина того, что мы сравниваем.
ip netns exec $NSS tcpdump -i sc -n -s 0 -w "$WORK/xhttp.pcap" 'tcp port 8443' >/dev/null 2>&1 &
sleep 0.5
ip netns exec $NSS "$XRAY" run -c "$WORK/srv.json" > "$WORK/xsrv.log" 2>&1 &
ip netns exec $NSC "$XRAY" run -c "$WORK/cli.json" > "$WORK/xcli.log" 2>&1 &
sleep 2
echo "== xhttp: качаю $MB МБ через туннель"
ip netns exec $NSC curl -s --limit-rate "$RATE" -o /dev/null \
    -w "   %{size_download} байт за %{time_total} с (предел $RATE/с)\n" \
    -x socks5://127.0.0.1:1080 http://10.216.1.1:8080/blob.bin
echo "   молчу $IDLE с, чтобы поймать keepalive"
sleep "$IDLE"
pkill -x tcpdump 2>/dev/null || true
ip netns pids $NSC 2>/dev/null | xargs -r kill 2>/dev/null || true
ip netns exec $NSS sh -c 'ip netns pids '"$NSS"' 2>/dev/null' >/dev/null 2>&1 || true
pkill -x xray 2>/dev/null || true
sleep 1

# ---- 2. xsteer --------------------------------------------------------------
priv_h=$("$GO" genkey); pub_h=$(printf '%s\n' "$priv_h" | "$GO" pubkey)
priv_a=$("$GO" genkey); pub_a=$(printf '%s\n' "$priv_a" | "$GO" pubkey)
cat > "$WORK/hub.conf" <<EOF
[Interface]
PrivateKey = $priv_h
Address    = 10.83.0.1/24
ListenPort = 443

[Peer]
PublicKey  = $pub_a
AllowedIPs = 10.83.0.2/32
EOF
cat > "$WORK/a.conf" <<EOF
[Interface]
PrivateKey = $priv_a
Address    = 10.83.0.2/24
SNI        = decoy.example.net

[Peer]
PublicKey  = $pub_h
AllowedIPs = 10.83.0.0/24
Endpoint   = 10.216.1.1:443
PersistentKeepalive = 15
EOF
chmod 600 "$WORK"/*.conf
# XS_FLAGS позволяет снять записи со старым форматом (--no-batch) и сравнить их с новым: без этого
# «стало лучше» пришлось бы утверждать по памяти.
xs_port=443
[ -n "$XS_STREAM" ] && xs_port=8443
ip netns exec $NSS tcpdump -i sc -n -s 0 -w "$WORK/xsteer.pcap" "tcp port $xs_port" >/dev/null 2>&1 &
sleep 0.5
if [ "$XS_IMPL" = c ]; then
    mkdir -p "$WORK/state"
    ip netns exec $NSS "$C_HUB" xsteer-hub --config "$WORK/hub.conf" \
        --state-dir "$WORK/state" > "$WORK/hub.log" 2>&1 &
else
    xs_hub_flags="${XS_FLAGS:-}"
    [ -n "$XS_STREAM" ] && xs_hub_flags="$xs_hub_flags --stream-port 8443"
    ip netns exec $NSS "$GO" hub "$WORK/hub.conf" $xs_hub_flags > "$WORK/hub.log" 2>&1 &
fi
sleep 1
# Одно соединение, а не по одному на ядро: сравниваем ФОРМУ одного потока с формой одного потока
# xhttp. Четыре соединения — отдельный признак, и о нём говорится в разборе отдельно.
if [ "$XS_IMPL" = c ]; then
    # Клиенту на C нужна спека: устройство и выход он берёт оттуда. Одно соединение — чтобы
    # сравнивать форму одного потока с формой одного потока xhttp.
    cat > "$WORK/a.json" <<EOF
{"schema":1,"lan_device":"lo","from_default":["10.83.0.0/24"],
 "outputs":{"xsa":{"kind":"xsteer","conf":"$WORK/a.conf"}},
 "channels":[]}
EOF
    STEER_XS_CONNS=1 ip netns exec $NSC env STEER_XS_CONNS=1 "$C_EXT" xsteer xsa \
        --spec "$WORK/a.json" --state-dir "$WORK/state" > "$WORK/a.log" 2>&1 &
else
    xs_cli_flags="${XS_FLAGS:-}"
    [ -n "$XS_STREAM" ] && xs_cli_flags="$xs_cli_flags --stream-port 8443"
    ip netns exec $NSC "$GO" up "$WORK/a.conf" --dev xsa --conns 1 --routes $xs_cli_flags \
        > "$WORK/a.log" 2>&1 &
fi
sleep 3
ip netns exec $NSS python3 -m http.server 8081 --bind 10.83.0.1 --directory "$WORK/www" \
    > "$WORK/httpd2.log" 2>&1 &
sleep 1
echo "== xsteer: качаю $MB МБ через туннель"
ip netns exec $NSC curl -s --limit-rate "$RATE" -o /dev/null \
    -w "   %{size_download} байт за %{time_total} с (предел $RATE/с)\n" \
    http://10.83.0.1:8081/blob.bin
echo "   молчу $IDLE с, чтобы поймать keepalive"
sleep "$IDLE"
pkill -x tcpdump 2>/dev/null || true
sleep 1

echo
python3 tests/wireshape.py --port "$xs_port" "$WORK/xsteer.pcap" --port 8443 "$WORK/xhttp.pcap"
if [ -n "${XC_KEEP:-}" ]; then
    cp "$WORK/xsteer.pcap" "$WORK/xhttp.pcap" /tmp/ 2>/dev/null || true
    echo "записи скопированы в /tmp"
fi
