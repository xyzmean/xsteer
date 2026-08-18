#!/bin/sh
# Живая проверка совместимости: клиент на Go против ХАБА НА C.
#
# ЗАЧЕМ ЭТОТ СТЕНД. Тесты в памяти доказывают, что реализация на Go согласована сама с собой:
# рукопожатие сходится, ключи совпадают, подделки не проходят. Но обещание порта другое — что
# десктопный клиент подключается к ТОМУ ЖЕ хабу, что роутер. Проверить это может только настоящий
# хаб на C: он разбирает наш ClientHello своим разбором, считает своё es и свой транскрипт, и любое
# расхождение в раскладке полей проявится ровно здесь и больше нигде.
#
# Обстановка: два пространства имён, соединённые veth. Хаб — бинарник из репозитория steer, пир —
# наш. Пересылку в ядре хаба выключаем явно: связь пир↔пир обязана работать без неё, трафик
# разворачивает сам хаб.
#
# Требует root (пространства имён и сырые сокеты), /dev/net/tun и собранный хаб.
#
#     sudo sh tests/interop.sh [секунд_на_замер]
set -eu
umask 077

SECS="${1:-5}"
HUB=${STEER_HUB_BIN:-../steer/build/steer-hub}
GO_XS=${XSTEER_BIN:-./build/xsteer}
NSH=xsi-hub
NSA=xsi-a
NSB=xsi-b
WORK=

fail=0
ok()   { printf '%-58s ok\n' "$1"; }
bad()  { printf '%-58s ПРОВАЛ\n' "$1"; fail=$((fail + 1)); }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1"; printf '     хочу: %s\n     есть: %s\n' "$2" "$3"; fi; }

cleanup() {
    for ns in $NSH $NSA $NSB; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    # XSI_KEEP=1 оставляет рабочий каталог с журналами: без него разбираться в упавшем прогоне
    # можно только по тому, что успело напечататься в терминал.
    if [ -n "$WORK" ] && [ -z "${XSI_KEEP:-}" ]; then rm -rf "$WORK"; else
        [ -n "$WORK" ] && echo "журналы оставлены в $WORK"
    fi
    return 0
}
# PIPE в списке не для красоты: вывод стенда часто читают через `| head`, и тогда оболочка гибнет
# от SIGPIPE. Без этого сигнала в trap уборка не выполняется — и в системе остаются клиенты в
# пространствах имён, которые потом портят ЛЮБОЙ следующий замер, а виноватой выглядит правка кода.
# Ровно это здесь и случилось: четыре прогона оставили по два процесса, и первые числа были ниже.
trap cleanup EXIT INT TERM PIPE HUP
cleanup

[ "$(id -u)" = 0 ] || { echo "нужен root: стенд делает пространства имён и сырые сокеты"; exit 2; }
[ -c /dev/net/tun ] || { echo "нет /dev/net/tun — туннель не поднять"; exit 2; }
[ -x "$HUB" ] || { echo "нет хаба $HUB — укажите STEER_HUB_BIN"; exit 2; }
[ -x "$GO_XS" ] || { echo "нет клиента $GO_XS — соберите: go build -o build/xsteer ./cmd/xsteer"; exit 2; }

WORK="$(mktemp -d)"; chmod 700 "$WORK"

for ns in $NSH $NSA $NSB; do ip netns add $ns; ip -n $ns link set lo up; done
for ns in $NSH $NSA $NSB; do ip netns exec $ns sysctl -qw net.ipv4.ip_forward=0; done
ip link add ha netns $NSH type veth peer name ah netns $NSA
ip link add hb netns $NSH type veth peer name bh netns $NSB
ip -n $NSH addr add 10.211.1.1/24 dev ha
ip -n $NSA addr add 10.211.1.2/24 dev ah
ip -n $NSH addr add 10.211.2.1/24 dev hb
ip -n $NSB addr add 10.211.2.2/24 dev bh
for p in "$NSH ha" "$NSA ah" "$NSH hb" "$NSB bh"; do set -- $p; ip -n "$1" link set "$2" up; done

# ---- ключи. Генерирует их НАШ клиент: так проверяется и это тоже — ключ, который хаб на C не
# принял бы, сделал бы стенд бесполезным ещё до рукопожатия.
priv_hub=$("$GO_XS" genkey); pub_hub=$(printf '%s\n' "$priv_hub" | "$GO_XS" pubkey)
priv_a=$("$GO_XS" genkey);   pub_a=$(printf '%s\n' "$priv_a" | "$GO_XS" pubkey)
priv_b=$("$GO_XS" genkey);   pub_b=$(printf '%s\n' "$priv_b" | "$GO_XS" pubkey)

cat > "$WORK/hub.conf" <<EOF
[Interface]
PrivateKey = $priv_hub
Address    = 10.78.0.1/24
ListenPort = 443

[Peer]
PublicKey  = $pub_a
AllowedIPs = 10.78.0.2/32

[Peer]
PublicKey  = $pub_b
AllowedIPs = 10.78.0.3/32
EOF

spoke() {   # $1 приватный, $2 адрес в туннеле, $3 адрес хаба, $4 файл
    cat > "$4" <<EOF
[Interface]
PrivateKey = $1
Address    = $2/24
SNI        = www.microsoft.com

[Peer]
PublicKey  = $pub_hub
AllowedIPs = 10.78.0.0/24
Endpoint   = $3:443
PersistentKeepalive = 15
EOF
}
spoke "$priv_a" 10.78.0.2 10.211.1.1 "$WORK/a.conf"
spoke "$priv_b" 10.78.0.3 10.211.2.1 "$WORK/b.conf"
chmod 600 "$WORK"/*.conf

# ---- запуск ------------------------------------------------------------------
mkdir -p "$WORK/state-hub"
ip netns exec $NSH "$HUB" xsteer-hub --config "$WORK/hub.conf" \
    --state-dir "$WORK/state-hub" > "$WORK/hub.log" 2>&1 &
sleep 0.6
# Перепроверка пути раз в три секунды: стенду надо УВИДЕТЬ работу согласования, а с боевым
# интервалом это заняло бы четыре минуты.
ip netns exec $NSA "$GO_XS" up "$WORK/a.conf" --dev xsa --routes --probe-ms 3000 \
    --state "$WORK/a.json" > "$WORK/a.log" 2>&1 &
ip netns exec $NSB "$GO_XS" up "$WORK/b.conf" --dev xsb --routes --probe-ms 3000 \
    --state "$WORK/b.json" > "$WORK/b.log" 2>&1 &

count_up() { grep -h 'поднялся' "$WORK/hub.log" 2>/dev/null | sed 's/.*пир \([^ ]*\) .*/\1/' \
             | sort -u | grep -c . || true; }
for i in $(seq 1 80); do
    [ "$(count_up)" -ge 2 ] && break
    sleep 0.25
done
peers=$(count_up)
check "рукопожатие: хаб на C опознал оба клиента на Go" "2" "$peers"
if [ "$peers" -lt 2 ]; then
    echo "--- журнал хаба ---";     cat "$WORK/hub.log"
    echo "--- журнал клиента A ---"; cat "$WORK/a.log"
    exit 1
fi

# Шифр называет каждая сторона: расхождение здесь означало бы, что согласование через порядок
# наборов шифров работает не так, как думает вторая сторона.
grep -q 'AES-128-GCM\|ChaCha20-Poly1305' "$WORK/a.log" && ok "шифр согласован и назван в журнале" \
    || bad "шифр согласован и назван в журнале"

if ip netns exec $NSA ping -c 3 -W 2 -q 10.78.0.1 >/dev/null 2>&1; then
    ok "клиент A → хаб: ping проходит"
else
    bad "клиент A → хаб: ping проходит"; tail -20 "$WORK/a.log"
fi

fwd=$(ip netns exec $NSH cat /proc/sys/net/ipv4/ip_forward)
check "ip_forward на хабе выключен" "0" "$fwd"
if ip netns exec $NSA ping -c 3 -W 2 -q 10.78.0.3 >/dev/null 2>&1; then
    ok "клиент A → клиент B через хаб: ping проходит"
else
    bad "клиент A → клиент B через хаб: ping проходит"; tail -5 "$WORK/hub.log"
fi

# ---- согласование MTU. Число НЕ зашито: его выясняют сами стороны, и зашитое проверяло бы, что
# стенд согласен с кодом, а не что согласование работает.
mtu_of() { ip netns exec $NSA cat /sys/class/net/xsa/mtu; }
settle() {
    _last=""; _same=0; _i=0
    while [ $_same -lt 8 ] && [ $_i -lt 120 ]; do
        _cur=$(mtu_of)
        if [ "$_cur" = "$_last" ]; then _same=$((_same + 1)); else _same=0; _last=$_cur; fi
        sleep 0.5; _i=$((_i + 1))
    done
    echo "$_last"
}
tmtu=$(settle)
link=$(ip netns exec $NSA cat /sys/class/net/ah/mtu)
want=$((link - 61))
check "MTU туннеля согласован по каналу $link" "$want" "$tmtu"

# Сужение пути под живой сессией. Режем НЕ MTU интерфейса, а длину пакета правилом на входе
# хаба, и это принципиально: интерфейс с меньшим MTU просто фрагментирует (мы намеренно не ставим
# DF), то есть большие пакеты продолжают доходить и сужения нет. Правило же ведёт себя как
# настоящая чёрная дыра на пути — ровно тот отказ, ради которого пробы и существуют.
narrow=1400          # столько несёт «новый» путь; предел туннеля станет 1400-61 = 1339
ip netns exec $NSH nft add table ip xsitest 2>/dev/null || true
ip netns exec $NSH nft add chain ip xsitest c '{ type filter hook input priority -300 ; }' 2>/dev/null || true
ip netns exec $NSH nft add rule ip xsitest c ip length gt $narrow drop 2>/dev/null || true
new_mtu=$(settle)
if [ "$new_mtu" -lt "$tmtu" ]; then
    ok "путь сузился: клиент опустил MTU ($tmtu → $new_mtu)"
else
    bad "путь сузился: клиент опустил MTU"; printf '     было %s, стало %s\n' "$tmtu" "$new_mtu"
fi
# Найденное значение обязано лежать ПОД настоящим пределом и не дальше зерна поиска от него:
# ниже — потерянная скорость, выше — чёрная дыра.
check "новый предел не выше настоящего" "1" \
      "$([ "$new_mtu" -le $((narrow - 61)) ] && echo 1 || echo 0)"
check "новый предел не дальше зерна от настоящего" "1" \
      "$([ "$new_mtu" -ge $((narrow - 61 - 8)) ] && echo 1 || echo 0)"
ip netns exec $NSH nft delete table ip xsitest 2>/dev/null || true
back=$(settle)
check "путь расширился — MTU вернулся" "$tmtu" "$back"

# ---- облик на проводе: каждая запись начинается с 17 03 03 ------------------
if command -v tcpdump >/dev/null; then
    ip netns exec $NSH timeout 4 tcpdump -i ha -n -x -c 20 'tcp port 443 and greater 100' \
        > "$WORK/dump.txt" 2>/dev/null || true
    # Заголовок записи лежит сразу за заголовками IP и TCP, то есть с 41-го байта пакета. tcpdump
    # печатает по 16 байт в строке начиная с 0x0000, поэтому байты 0x0028..0x002a — третья строка.
    recs=$(grep -c '0x0020:.* 1703' "$WORK/dump.txt" 2>/dev/null || true)
    if [ "${recs:-0}" -gt 0 ]; then
        ok "на проводе видны записи TLS (17 03 03): $recs шт."
    else
        # Не провал: смещение зависит от опций и от версии tcpdump. Но сказать надо.
        printf '%-58s не проверено\n' "облик на проводе (17 03 03)"
    fi
fi

# ---- скорость. Не обещание, а измерение: число печатается, чтобы его можно было сравнить с
# роутерной половиной и с эталонным WireGuard на той же машине.
if command -v iperf3 >/dev/null; then
    ip netns exec $NSH iperf3 -s -D -B 10.78.0.1 --logfile "$WORK/iperf-s.log" 2>/dev/null || true
    sleep 0.5
    speed() {   # $1 — число потоков
        if ip netns exec $NSA iperf3 -c 10.78.0.1 -t "$SECS" -P "$1" -J > "$WORK/iperf-$1.json" 2>/dev/null; then
            awk '/sum_sent/,/}/' "$WORK/iperf-$1.json" | awk -F'[:,]' \
                '/bits_per_second/ {printf "%.0f", $2/1000000; exit}'
        fi
    }
    one=$(speed 1)
    [ -n "$one" ] && ok "iperf3, один поток: ${one} Мбит/с" || printf '%-58s не измерено\n' "iperf3, один поток"
    # ЧЕТЫРЕ ПОТОКА печатаются, но НЕ проверяются. Причина в том, как трафик попадает в соединения:
    # раскладывает его ядро, симметричным хешем потока по очередям устройства, и на четырёх потоках
    # оно иногда сваливает все в одну очередь — то есть в одно соединение и одно ядро. Замерено на
    # шести прогонах: 557, 1148, 1153, 1158, 1178 и 1776 Мбит/с. Провал в первом случае относится к
    # раскладке, а не к туннелю, и проверять им многопоточность значило бы получить стенд, который
    # падает раз в шесть запусков без всякой правки кода.
    many=$(speed 4)
    [ -n "$many" ] && ok "iperf3, четыре потока суммарно: ${many} Мбит/с" \
        || printf '%-58s не измерено\n' "iperf3, четыре потока"
    # А вот на шестнадцати потоках раскладка ровная по любому разумному хешу, и здесь суммарная
    # скорость ОБЯЗАНА превышать один поток: иначе многопоточности нет вовсе.
    lots=$(speed 16)
    if [ -n "$lots" ] && [ -n "$one" ]; then
        ok "iperf3, шестнадцать потоков суммарно: ${lots} Мбит/с"
        check "суммарная скорость растёт с числом потоков" "1" \
              "$([ "$lots" -gt "$one" ] && echo 1 || echo 0)"
    else
        printf '%-58s не измерено\n' "iperf3, шестнадцать потоков"
    fi
fi

echo
if [ "$fail" -gt 0 ]; then
    echo "ЕСТЬ ПРОВАЛЫ: $fail"
    echo "--- журнал клиента A ---"; tail -30 "$WORK/a.log"
    echo "--- журнал хаба ---";      tail -30 "$WORK/hub.log"
    exit 1
fi
echo "все проверки прошли"
