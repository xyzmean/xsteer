#!/bin/sh
# Стенд обвязки: xs-quick поднимает и снимает настоящий туннель в пространствах имён.
#
# ЗАЧЕМ ОН НУЖЕН ОТДЕЛЬНО ОТ ОСТАЛЬНЫХ СТЕНДОВ. Всё, что делает xs-quick, — это работа с
# ПОБОЧНЫМИ ЭФФЕКТАМИ: крючки исполняются или нет, номер процесса записан верно или нет,
# устройство убрано или осталось. Ни одно из этого не проверяется разбором кода, и каждое уже
# ломалось: первая версия скрипта держала открытым stdout вызывающего (и всякий, кто читал её
# вывод, висел вечно), а номер процесса брала из $! — то есть у setsid, а не у клиента, и «снял
# туннель» означало «забыл про туннель».
#
#     sudo sh tests/quick.sh
set -eu
GO=${XSTEER_BIN:-./build/xsteer}
Q=${XS_QUICK:-./contrib/xs-quick}
NSH=xq-hub
NSA=xq-a
WORK=
fails=0

ok()  { printf '    %-56s ok\n' "$1"; }
bad() { printf '    %-56s ПРОВАЛ\n' "$1"; fails=$((fails + 1)); }

teardown_ns() {
	for ns in $NSH $NSA; do
		ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null || true
		ip netns del $ns 2>/dev/null || true
	done
	return 0
}
cleanup() { teardown_ns; [ -n "$WORK" ] && [ -z "${XQ_KEEP:-}" ] && rm -rf "$WORK"; return 0; }
trap cleanup EXIT INT TERM HUP
cleanup

[ "$(id -u)" = 0 ] || { echo "нужен root"; exit 2; }
[ -c /dev/net/tun ] || { echo "нет /dev/net/tun"; exit 2; }
[ -x "$GO" ] || { echo "нет $GO (соберите: go build -o build/xsteer ./cmd/xsteer)"; exit 2; }
[ -r "$Q" ] || { echo "нет $Q"; exit 2; }

WORK="$(mktemp -d)"; chmod 700 "$WORK"
ph=$("$GO" genkey); Ph=$(printf '%s\n' "$ph" | "$GO" pubkey)
pa=$("$GO" genkey); Pa=$(printf '%s\n' "$pa" | "$GO" pubkey)
cat > "$WORK/hub.conf" <<EOF
[Interface]
PrivateKey = $ph
Address    = 10.88.0.1/24
ListenPort = 443

[Peer]
PublicKey  = $Pa
AllowedIPs = 10.88.0.2/32
EOF
# Конфигурация пира НАРОЧНО содержит то, что клиент отвергает: крючки и Table. Их обязана взять на
# себя обвязка, а клиенту достаться файл без них.
cat > "$WORK/qt.conf" <<EOF
[Interface]
PrivateKey = $pa
Address    = 10.88.0.2/24
SNI        = www.microsoft.com
Table      = off
PreUp      = sh -c 'echo PreUp:%i >> $WORK/hooks.log'
PostUp     = sh -c 'echo PostUp:%i >> $WORK/hooks.log'
PreDown    = sh -c 'echo PreDown:%i >> $WORK/hooks.log'
PostDown   = sh -c 'echo PostDown:%i >> $WORK/hooks.log'

[Peer]
PublicKey  = $Ph
AllowedIPs = 0.0.0.0/0
Endpoint   = 10.221.1.1:443
PersistentKeepalive = 15
EOF
chmod 600 "$WORK"/*.conf

for ns in $NSH $NSA; do ip netns add $ns; ip -n $ns link set lo up; done
ip link add ha netns $NSH type veth peer name ah netns $NSA
ip -n $NSH addr add 10.221.1.1/24 dev ha
ip -n $NSA addr add 10.221.1.2/24 dev ah
ip -n $NSH link set ha up; ip -n $NSA link set ah up
ip netns exec $NSH "$GO" hub "$WORK/hub.conf" > "$WORK/hub.log" 2>&1 &
sleep 1.2

# timeout ВНУТРИ функции, а не перед её вызовом: timeout — это программа, и функцию оболочки она
# запустить не может («timeout: failed to run command Qrun»). Стенд на этом уже соврал: подъём не
# происходил вовсе, а проверки «устройство убрано» и «процесс остановлен» при этом проходили.
Qrun() { timeout 30 ip netns exec $NSA env XSTEER_BIN="$GO" XS_RUNDIR="$WORK/run" "$Q" "$@"; }

echo "== обвязка xs-quick =="

# 1. Вырезание: файл для клиента не должен содержать ни одного отвергаемого ключа и обязан пройти
# ту же проверку, которой пользуется сам клиент.
Qrun strip "$WORK/qt.conf" > "$WORK/stripped.conf"; chmod 600 "$WORK/stripped.conf"
if [ "$(grep -icE '^[[:space:]]*(pre|post)(up|down)|^[[:space:]]*table|^[[:space:]]*fwmark' "$WORK/stripped.conf")" = 0 ]; then
	ok "strip убирает крючки и Table"
else
	bad "strip убирает крючки и Table"
fi
if "$GO" check "$WORK/stripped.conf" >/dev/null 2>&1; then
	ok "вырезанный файл проходит xsteer check"
else
	bad "вырезанный файл проходит xsteer check"
fi

# 2. Подъём. Вызов обязан ВЕРНУТЬСЯ: фоновый клиент не должен держать наш вывод открытым.
if Qrun up "$WORK/qt.conf" > "$WORK/up.log" 2>&1; then
	ok "up возвращает управление (не держит stdout)"
else
	bad "up возвращает управление (не держит stdout)"
	sed 's/^/      /' "$WORK/up.log" 2>/dev/null || true
fi
grep -q "PreUp:qt" "$WORK/hooks.log" 2>/dev/null && ok "PreUp исполнен" || bad "PreUp исполнен"
grep -q "PostUp:qt" "$WORK/hooks.log" 2>/dev/null && ok "PostUp исполнен" || bad "PostUp исполнен"

# 3. Номер процесса обязан указывать на КЛИЕНТА, а не на промежуточную оболочку: иначе down его не
# снимет. Проверяем по имени исполняемого файла.
pid="$(cat "$WORK/run/qt.pid" 2>/dev/null || echo)"
if [ -n "$pid" ] && [ -r "/proc/$pid/comm" ] && grep -q xsteer "/proc/$pid/comm"; then
	ok "в pid-файле номер самого клиента"
else
	bad "в pid-файле номер самого клиента (там $(cat "/proc/$pid/comm" 2>/dev/null || echo нет))"
fi

# 4. Туннель несёт трафик, и состояние читается без файла конфигурации.
if ip netns exec $NSA ping -c 2 -W 3 -q 10.88.0.1 >/dev/null 2>&1; then
	ok "туннель несёт трафик"
else
	bad "туннель несёт трафик"
fi
if Qrun status "$WORK/qt.conf" 2>/dev/null | grep -q "работает"; then
	ok "status показывает работу"
else
	bad "status показывает работу"
fi

# 5. Table = off обязан удержать маршрут по умолчанию у физического интерфейса, даже когда пир
# заворачивает 0.0.0.0/0. Связный маршрут своей сети при этом ставит ядро — это норма.
if ip netns exec $NSA ip route show default 2>/dev/null | grep -q qt; then
	bad "Table = off удержал маршрут по умолчанию"
else
	ok "Table = off удержал маршрут по умолчанию"
fi

# 6. Снятие: крючки, исчезнувшее устройство и убитый процесс.
if Qrun down "$WORK/qt.conf" > "$WORK/down.log" 2>&1; then
	ok "down возвращает управление"
else
	bad "down возвращает управление"
fi
grep -q "PreDown:qt" "$WORK/hooks.log" 2>/dev/null && ok "PreDown исполнен" || bad "PreDown исполнен"
grep -q "PostDown:qt" "$WORK/hooks.log" 2>/dev/null && ok "PostDown исполнен" || bad "PostDown исполнен"
if ip netns exec $NSA ip link show qt >/dev/null 2>&1; then
	bad "устройство убрано"
else
	ok "устройство убрано"
fi
if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
	bad "процесс клиента остановлен"
else
	ok "процесс клиента остановлен"
fi

echo
if [ "$fails" -gt 0 ]; then echo "ЕСТЬ ПРОВАЛЫ: $fails"; exit 1; fi
echo "обвязка работает"
