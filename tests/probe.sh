#!/bin/sh
# Активное зондирование: что видит прибор, постучавшийся на порт хаба.
#
# ЗАЧЕМ ЭТОТ СТЕНД. Устойчивость к зондированию — не свойство кода, а свойство ОТВЕТА, и проверить
# её можно только настоящим клиентом TLS, который ничего не знает про наш протокол. Здесь это
# openssl s_client: он присылает подлинный ClientHello и печатает всё, что получил в ответ.
#
# Проверяются все режимы разом, потому что сравнивать их надо между собой: каждый по отдельности
# «работает», а вопрос в том, чем ответ отличается от настоящего сервера.
#
#     sudo sh tests/probe.sh
set -eu
umask 077

GO=${XSTEER_BIN:-./build/xsteer}
NSH=xsp-hub
NSA=xsp-a
WORK=
fails=0
ok()  { printf '    %-56s ok\n' "$1"; }
bad() { printf '    %-56s ПРОВАЛ\n' "$1"; fails=$((fails + 1)); }

cleanup() {
    for ns in $NSH $NSA; do
        ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
        ip netns del $ns 2>/dev/null || true
    done
    [ -n "$WORK" ] && [ -z "${XSP_KEEP:-}" ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT INT TERM PIPE HUP
cleanup

[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 2; }
[ -x "$GO" ] || { echo "нет $GO"; exit 2; }
command -v openssl >/dev/null || { echo "нет openssl — прибором быть нечем"; exit 2; }

WORK="$(mktemp -d)"; chmod 700 "$WORK"
for ns in $NSH $NSA; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add ha netns $NSH type veth peer name ah netns $NSA
ip -n $NSH addr add 10.213.1.1/24 dev ha
ip -n $NSA addr add 10.213.1.2/24 dev ah
ip -n $NSH link set ha up; ip -n $NSA link set ah up

# Ключи и конфигурации: пир нужен, чтобы проверить, что защита от зондирования не мешает своим.
priv_hub=$("$GO" genkey); pub_hub=$(printf '%s\n' "$priv_hub" | "$GO" pubkey)
priv_a=$("$GO" genkey);   pub_a=$(printf '%s\n' "$priv_a" | "$GO" pubkey)
cat > "$WORK/hub.conf" <<EOF
[Interface]
PrivateKey = $priv_hub
Address    = 10.80.0.1/24
ListenPort = 443

[Peer]
PublicKey  = $pub_a
AllowedIPs = 10.80.0.2/32
EOF
cat > "$WORK/a.conf" <<EOF
[Interface]
PrivateKey = $priv_a
Address    = 10.80.0.2/24
SNI        = www.example.com

[Peer]
PublicKey  = $pub_hub
AllowedIPs = 10.80.0.0/24
Endpoint   = 10.213.1.1:443
PersistentKeepalive = 15
EOF
chmod 600 "$WORK"/*.conf

# Сайт-прикрытие: настоящий сервер TLS со своим сертификатом. Он живёт в пространстве хаба, потому
# что именно хаб к нему дозванивается; прибор о его существовании знать не должен вовсе.
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$WORK/k.pem" -out "$WORK/c.pem" \
    -days 2 -subj "/CN=decoy.example.net" >/dev/null 2>&1
ip netns exec $NSH openssl s_server -accept 8443 -cert "$WORK/c.pem" -key "$WORK/k.pem" \
    -www -quiet > "$WORK/decoy.log" 2>&1 &
sleep 0.5

# Прибор: подлинный ClientHello и всё, что пришло в ответ.
probe() {   # $1 — куда писать
    ip netns exec $NSA timeout 8 openssl s_client -connect 10.213.1.1:443 \
        -servername www.microsoft.com -brief < /dev/null > "$1" 2>&1 || true
}

run_hub() {   # $1 — имя режима для журнала, дальше ключи хаба
    HUBLOG="$WORK/hub-$1.log"; shift
    # Устройство хабу нужно: без него у него нет собственного адреса в туннеле, и проверка «свой
    # пир не только поднялся, но и несёт трафик» проверяла бы не то. Первая версия стенда запускала
    # хаб с --no-tun и падала именно на этом — причём в самом важном месте, где надо было убедиться,
    # что защита от зондирования не мешает своим.
    ip netns exec $NSH "$GO" hub "$WORK/hub.conf" "$@" > "$HUBLOG" 2>&1 &
    HUBPID=$!
    sleep 0.8
}
stop_hub() {
    # Ждём НАСТОЯЩЕГО выхода, а не «полсекунды и, наверное, ушёл».
    #
    # Причина не в аккуратности: уходя, хаб снимает свою цепочку в nftables, и если новый успеет
    # добавить её раньше, чем старый снял, — старый снесёт правило нового. Тогда ядро начинает
    # отвечать RST на рукопожатия, и стенд падает в клетке, к которой это не имеет отношения. Ровно
    # это здесь и случилось: режим proxy «не работал», хотя не работала уборка предыдущей клетки.
    kill "$HUBPID" 2>/dev/null || true
    for _ in $(seq 1 60); do kill -0 "$HUBPID" 2>/dev/null || break; sleep 0.1; done
    # Клиенты, если были: их тоже надо убрать между клетками.
    ip netns pids $NSA 2>/dev/null | xargs -r kill 2>/dev/null || true
    sleep 0.3
    # Сайт-прикрытие поднимаем заново: s_server уходит после первого соединения не всегда, но
    # надёжнее не зависеть от этого.
    if ! ip netns exec $NSH ss -ltn 2>/dev/null | grep -q 8443; then
        ip netns exec $NSH openssl s_server -accept 8443 -cert "$WORK/c.pem" -key "$WORK/k.pem" \
            -www -quiet >> "$WORK/decoy.log" 2>&1 &
        sleep 0.4
    fi
}

echo "== что видит прибор =="

echo
echo "-- режим alert (как в движке на C) --"
run_hub alert --decoy alert
probe "$WORK/p-alert.txt"
sed 's/^/       /' "$WORK/p-alert.txt" | head -6
if grep -qi 'handshake failure\|alert\|no protocols available\|ssl' "$WORK/p-alert.txt"; then
    ok "прибор получил отказ TLS (то есть узнал, что здесь не обычный сервер)"
else
    bad "прибор получил отказ TLS"
fi
stop_hub

echo
echo "-- режим silent --"
run_hub silent --decoy silent
probe "$WORK/p-silent.txt"
sed 's/^/       /' "$WORK/p-silent.txt" | head -4
if [ ! -s "$WORK/p-silent.txt" ] || ! grep -q 'Protocol' "$WORK/p-silent.txt"; then
    ok "рукопожатия нет (порт открыт и молчит — отличимо сильнее отказа)"
else
    bad "рукопожатия нет"
fi
stop_hub

echo
echo "-- режим proxy: соединение отдаётся настоящему серверу --"
run_hub proxy --decoy proxy --decoy-dest 127.0.0.1:8443
probe "$WORK/p-proxy.txt"
sed 's/^/       /' "$WORK/p-proxy.txt" | head -10
if grep -q 'decoy.example.net' "$WORK/p-proxy.txt"; then
    ok "прибор получил ПОДЛИННЫЙ сертификат сайта-прикрытия"
else
    bad "прибор получил подлинный сертификат сайта-прикрытия"
fi
if grep -qi 'Protocol.*TLSv1.3\|Ciphersuite' "$WORK/p-proxy.txt"; then
    ok "рукопожатие TLS прошло целиком — как на обычном сайте"
else
    bad "рукопожатие TLS прошло целиком"
fi
if grep -q 'отдаю настоящему серверу' "$HUBLOG"; then
    ok "хаб назвал это в журнале (с ограничителем частоты)"
else
    bad "хаб назвал это в журнале"
fi

# И главное: защита не должна мешать своим. Пир поднимается на том же хабе, в том же режиме.
ip netns exec $NSA "$GO" up "$WORK/a.conf" --dev xsa --probe-ms 3000 > "$WORK/a.log" 2>&1 &
for i in $(seq 1 60); do grep -q 'поднялся' "$HUBLOG" && break; sleep 0.25; done
if grep -q 'поднялся' "$HUBLOG"; then
    ok "свой пир поднялся на том же хабе в режиме proxy"
else
    bad "свой пир поднялся на том же хабе в режиме proxy"; tail -6 "$WORK/a.log"
fi
if ip netns exec $NSA ping -c 2 -W 2 -q 10.80.0.1 >/dev/null 2>&1; then
    ok "и несёт трафик"
else
    bad "и несёт трафик"
fi
stop_hub

echo
if [ "$fails" -gt 0 ]; then echo "ЕСТЬ ПРОВАЛЫ: $fails"; exit 1; fi
echo "все проверки прошли"
