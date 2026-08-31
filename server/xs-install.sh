#!/bin/bash
# Хаб xsteer на VPS: установка, пиры, снятие. По образцу wireguard-install от angristan — тот же
# порядок вопросов, то же меню при повторном запуске, тот же способ отдать готовый конфиг. Человек,
# ставивший WireGuard тем скриптом, здесь узнаёт всё, кроме названий.
#
# ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ server/xs_install.sh В ДВИЖКЕ НА C. Тот ставит половину на C и берёт
# готовый статический бинарник, потому что собирать mbedtls на VPS нельзя незаметно правильно.
# Здесь реализация на Go: один файл без зависимостей, и вопрос «где взять криптографию» не стоит
# вовсе. Отсюда упрощение — но и отличие по существу: у этой половины есть РЕЖИМ ПОТОКА (записи по
# настоящему TCP), и он единственный, которым работают пиры на Windows. Установщик спрашивает про
# него прямо, потому что забыть его означает «хаб стоит, а десктопы не подключаются».
#
# ПОЧЕМУ bash, А НЕ sh, КАК ОСТАЛЬНЫЕ СКРИПТЫ ПРОЕКТА. Ради `read -e -i`: значения по умолчанию,
# которые можно поправить на месте. Именно оно превращает установку в «нажать enter шесть раз». На
# VPS bash есть всегда; если его нет — ставьте руками по docs/deploy.md.
set -u

RED='\033[0;31m'
ORANGE='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

PREFIX=/usr/local/sbin
BIN="$PREFIX/xsteer"
CONFDIR=/etc/xsteer
CONF="$CONFDIR/hub.conf"
PARAMS="$CONFDIR/params"
UNIT=/etc/systemd/system/xsteer-hub.service
NATUNIT=/etc/systemd/system/xsteer-nat.service
NATBIN=/usr/local/sbin/xsteer-nat
RELEASES=https://github.com/xyzmean/xsteer/releases/latest/download

# Спросить с приглашением и значением по умолчанию.
#
# ЗАЧЕМ ОТДЕЛЬНОЙ ФУНКЦИЕЙ, а не `read` на месте: цикл вида `until <проверка>; do read ...; done`
# при КОНЦЕ ВВОДА крутится вечно и печатает приглашение в никуда. Случается это не в теории — так
# ведёт себя любой запуск не с терминала: `bash xs-install.sh < answers`, прогон из чужого скрипта,
# ssh без -t. Установщик в этом случае обязан отказать, а не висеть.
function ask() { # ask ПЕРЕМЕННАЯ "приглашение" ["по умолчанию"]
	local __var="$1" __prompt="$2" __def="${3:-}" __val=""
	if ! read -rp "$__prompt" -e -i "$__def" __val; then
		echo ""
		echo -e "${RED}ввод закончился${NC} — прерываюсь. Скрипт спрашивает, и запускать его надо"
		echo "с терминала: bash xs-install.sh"
		exit 1
	fi
	printf -v "$__var" '%s' "$__val"
}

function anykey() {
	if ! read -n1 -r -p "$1"; then echo ""; echo -e "${RED}ввод закончился${NC} — прерываюсь."; exit 1; fi
	echo ""
}

function isRoot() {
	[ "${EUID:-$(id -u)}" = 0 ] || { echo -e "${RED}нужен root${NC}"; exit 1; }
}

function checkTun() {
	if [ ! -c /dev/net/tun ]; then
		echo -e "${RED}нет /dev/net/tun${NC}"
		echo "На LXC и OpenVZ устройства TUN часто нет вовсе. Тогда хаб может работать только"
		echo "трафиком пир↔пир (ключ --no-tun), и выхода в интернет через него не будет."
		exit 1
	fi
}

function checkSystemd() {
	command -v systemctl >/dev/null 2>&1 || { echo -e "${RED}нет systemd${NC} — юнит ставить некуда"; exit 1; }
}

function checkNft() {
	command -v nft >/dev/null 2>&1 && return 0
	echo -e "${ORANGE}нет nft${NC} — masquerade поставить будет нечем."
	echo "Поставьте nftables (apt install nftables) или откажитесь от NAT в вопросах ниже."
}

function initialCheck() { isRoot; checkSystemd; checkTun; checkNft; }

# ---- бинарник ----------------------------------------------------------------

# Берём готовый файл из релиза и ПРОВЕРЯЕМ сумму по SHA256SUMS того же релиза.
#
# Проверка обязательна, а не «хорошо бы»: без неё установщик молча ставит то, что отдал сервер, и
# подмена файла не отличается от обновления. Сумма берётся из того же релиза — это не защита от
# подмены самого релиза (для неё нужна подпись), но она ловит порчу при передаче и подмену
# отдельного файла.
function getHubBinary() {
	if [ -x "$BIN" ]; then
		local have; have="$("$BIN" version 2>/dev/null | head -1)"
		echo "уже стоит: ${have:-неизвестная версия} ($BIN)"
		ask REUSE "Взять свежий из релиза? [y/n]: " n
		[[ ${REUSE} =~ ^[yY]$ ]] || return 0
	fi
	local arch
	case "$(uname -m)" in
	x86_64|amd64) arch=amd64 ;;
	aarch64|arm64) arch=arm64 ;;
	*) echo -e "${RED}архитектура $(uname -m) не собирается в релизе${NC}"
	   echo "Соберите сами: go build -o $BIN ./cmd/xsteer"; exit 1 ;;
	esac
	command -v curl >/dev/null 2>&1 || { echo -e "${RED}нет curl${NC}"; exit 1; }
	local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
	echo "качаю xsteer-linux-${arch}.tar.gz..."
	curl -fsSL -o "$tmp/x.tar.gz" "$RELEASES/xsteer-linux-${arch}.tar.gz" ||
		{ echo -e "${RED}не скачалось${NC}"; exit 1; }
	if curl -fsSL -o "$tmp/SHA256SUMS" "$RELEASES/SHA256SUMS" 2>/dev/null; then
		local want got
		want="$(awk -v f="xsteer-linux-${arch}.tar.gz" '$2 == f {print $1}' "$tmp/SHA256SUMS")"
		got="$(sha256sum "$tmp/x.tar.gz" | awk '{print $1}')"
		if [ -z "$want" ]; then
			echo -e "${ORANGE}в SHA256SUMS нет строки для этого файла${NC} — ставлю без проверки суммы"
		elif [ "$want" != "$got" ]; then
			echo -e "${RED}сумма не сошлась${NC}: ждали $want, получили $got"
			echo "Это либо порча при передаче, либо подмена файла. Не ставлю."
			exit 1
		else
			echo "сумма сошлась"
		fi
	else
		echo -e "${ORANGE}SHA256SUMS не скачался${NC} — ставлю без проверки суммы"
	fi
	tar -xzf "$tmp/x.tar.gz" -C "$tmp" || { echo -e "${RED}архив не распаковался${NC}"; exit 1; }
	install -m 0755 "$tmp/xsteer" "$BIN" || exit 1
	echo "поставлен: $("$BIN" version | head -1)"
}

# ---- вопросы -----------------------------------------------------------------

function installQuestions() {
	echo "Хаб xsteer — установка."
	echo ""
	echo "Несколько вопросов; на всё, что устраивает, достаточно нажать enter."
	echo ""

	HUB_PUB_IP="$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)"
	ask HUB_PUB_IP "Публичный адрес IPv4 этого сервера: " "${HUB_PUB_IP}"

	local nic_guess
	nic_guess="$(ip -4 route ls | grep default | awk '/dev/ {for (i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -1)"
	until [[ ${HUB_NIC:-} =~ ^[a-zA-Z0-9_.-]+$ ]]; do
		ask HUB_NIC "Внешний интерфейс (через него уходит трафик пиров): " "${nic_guess}"
	done

	# ТРАНСПОРТ — главный вопрос, и он не косметический.
	#
	# Поддельный TCP экономит повторные передачи (потеря наружу остаётся потерей внутреннего
	# пакета, а не превращается в задержку), но он невозможен на Windows без драйвера-перехватчика.
	# Режим потока работает всюду и выглядит настоящим TLS полнее, ценой TCP внутри TCP. Пиры на
	# Windows умеют ТОЛЬКО поток, и это решает выбор чаще всего.
	echo ""
	echo "Каким транспортом ходят пиры?"
	echo "   1) поток (настоящий TCP) — работает всюду, включая Windows; так ходит xsteer-gui"
	echo "   2) поддельный TCP — без повторных передач, но Windows так не умеет"
	echo "   3) оба, на разных портах — порт поддельного нельзя делить со слушающим сокетом"
	until [[ ${HUB_MODE:-} =~ ^[123]$ ]]; do ask HUB_MODE "Выбор [1-3]: " 1; done

	local portq="Порт хаба [1-65535]: "
	[ "$HUB_MODE" = 3 ] && portq="Порт ПОДДЕЛЬНОГО TCP [1-65535]: "
	# 443 по умолчанию не ради красоты: на этом порту поток, похожий на TLS, не выделяется среди
	# остального. Другой порт работает так же, но заметен сам по себе.
	until [[ ${HUB_PORT:-} =~ ^[0-9]+$ ]] && [ "${HUB_PORT}" -ge 1 ] && [ "${HUB_PORT}" -le 65535 ]; do
		ask HUB_PORT "$portq" 443
	done
	if [ "$HUB_MODE" = 3 ]; then
		until [[ ${HUB_SPORT:-} =~ ^[0-9]+$ ]] && [ "${HUB_SPORT}" -ge 1 ] && [ "${HUB_SPORT}" -le 65535 ] &&
			[ "${HUB_SPORT}" != "${HUB_PORT}" ]; do
			ask HUB_SPORT "Порт ПОТОКА (другой, чем у поддельного) [1-65535]: " 8443
		done
	else
		HUB_SPORT="$HUB_PORT"
	fi

	# Занятость порта проверяем сразу. Для поддельного TCP это условие работы: слушающий сокет
	# ядра на его порту отвечал бы SYN-ACK нашим же пирам, и рукопожатие ломалось бы через раз.
	local check_ports="$HUB_PORT"
	[ "$HUB_MODE" = 3 ] && check_ports="$HUB_PORT $HUB_SPORT"
	local p
	for p in $check_ports; do
		if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}\$"; then
			echo -e "${RED}порт ${p} уже слушает чей-то сокет${NC}"
			echo "Освободите его или выберите другой."
			exit 1
		fi
	done

	until [[ ${HUB_SUBNET:-} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; do
		ask HUB_SUBNET "Сеть туннеля (хаб займёт первый адрес): " 10.9.0.0/24
	done
	HUB_BASE="$(echo "${HUB_SUBNET%/*}" | awk -F. '{print $1"."$2"."$3}')"
	HUB_PLEN="${HUB_SUBNET#*/}"
	HUB_ADDR="${HUB_BASE}.1"

	# Имя устройства: если xshub0 занято (рядом работает другой хаб), берём следующее свободное —
	# иначе второй хаб не поднимется, а ошибка об этом невнятная.
	HUB_DEV=xshub0
	if ip link show "$HUB_DEV" >/dev/null 2>&1; then
		local i=1
		while ip link show "xshub${i}" >/dev/null 2>&1; do i=$((i + 1)); done
		HUB_DEV="xshub${i}"
		echo ""
		echo "Устройство xshub0 занято — этот хаб возьмёт ${HUB_DEV}."
	fi

	echo ""
	echo "Пиры могут ходить через хаб в интернет — тогда нужен masquerade на внешнем интерфейсе."
	echo "Правило ставится в ОТДЕЛЬНУЮ таблицу nft (xsteer_nat): чужих правил установщик не"
	echo "трогает и не переписывает."
	ask HUB_NAT "Поставить masquerade и включить пересылку? [y/n]: " y

	echo ""
	echo "Готово, вопросов больше нет."
	anykey "Нажмите любую клавишу, чтобы продолжить..."
	echo ""
}

function writeParams() {
	# Секретов здесь НЕТ: приватный ключ живёт только в hub.conf с правами 0600. Этот файл читают
	# меню и, возможно, человек — ключу в нём делать нечего.
	cat >"$PARAMS" <<EOF
HUB_PUB_IP=${HUB_PUB_IP}
HUB_NIC=${HUB_NIC}
HUB_MODE=${HUB_MODE}
HUB_PORT=${HUB_PORT}
HUB_SPORT=${HUB_SPORT}
HUB_SUBNET=${HUB_SUBNET}
HUB_BASE=${HUB_BASE}
HUB_PLEN=${HUB_PLEN}
HUB_ADDR=${HUB_ADDR}
HUB_DEV=${HUB_DEV}
HUB_PUB_KEY=${HUB_PUB_KEY}
HUB_NAT=${HUB_NAT}
EOF
	chmod 0600 "$PARAMS"
}

# hubArgs — ключи запуска по выбранному транспорту. Одна функция, потому что эти же ключи нужны и
# юниту, и подсказкам в конце: два места, где их собирают по-разному, однажды разойдутся.
function hubArgs() {
	case "$HUB_MODE" in
	1) echo "--stream-port ${HUB_SPORT} --stream-only --dev ${HUB_DEV}" ;;
	2) echo "--dev ${HUB_DEV}" ;;
	3) echo "--stream-port ${HUB_SPORT} --dev ${HUB_DEV}" ;;
	esac
}

function installHub() {
	installQuestions
	getHubBinary

	mkdir -p "$CONFDIR"; chmod 0700 "$CONFDIR"

	local priv pub
	priv="$("$BIN" genkey)" || { echo "ключи не сделались"; exit 1; }
	pub="$(printf '%s\n' "$priv" | "$BIN" pubkey)" || { echo "ключи не сделались"; exit 1; }
	HUB_PUB_KEY="$pub"

	# ListenPort пишется ВСЕГДА, даже когда поддельный TCP не поднимается: разбор конфигурации
	# требует его у роли хаба, и без него файл не пройдёт проверку.
	( umask 077; cat >"$CONF" <<EOF
[Interface]
PrivateKey = $priv
Address    = ${HUB_ADDR}/${HUB_PLEN}
ListenPort = ${HUB_PORT}
EOF
	)
	writeParams

	cat >"$UNIT" <<EOF
[Unit]
Description=xsteer — хаб звезды
After=network-online.target
Wants=network-online.target
Documentation=https://github.com/xyzmean/xsteer

[Service]
Type=simple
ExecStart=$BIN hub $CONF $(hubArgs)
# Устройство, маршруты и сырой сокет — это CAP_NET_ADMIN и CAP_NET_RAW, больше ничего не нужно.
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
DeviceAllow=/dev/net/tun rw
ProtectSystem=strict
ReadWritePaths=$CONFDIR
ProtectHome=yes
PrivateTmp=yes
# Выход процесса — всегда отказ, поэтому поднимаем заново всегда, но с паузой: сеть, которой ещё
# нет, не станет доступнее от частых попыток.
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

	if [[ ${HUB_NAT} =~ ^[yY]$ ]]; then
		# Пересылка — это УСЛОВИЕ РАБОТЫ того, что мы ставим, а не чужая настройка: без неё пир с
		# 0.0.0.0/0 не выйдет в интернет вовсе.
		cat >/etc/sysctl.d/99-xsteer.conf <<'EOF'
# Хабу xsteer нужна пересылка: трафик пиров выходит наружу через ядро.
net.ipv4.ip_forward = 1
EOF
		sysctl -q --system

		# Своя таблица nft и свой юнит, который её ставит при загрузке. Отдельная таблица —
		# принципиально: чужие правила не переписываются, а снятие хаба уносит ровно своё.
		cat >"$NATBIN" <<EOF
#!/bin/sh
# masquerade для трафика пиров xsteer. Своя таблица: чужих правил не касаемся.
nft delete table ip xsteer_nat 2>/dev/null
nft add table ip xsteer_nat
nft add chain ip xsteer_nat post '{ type nat hook postrouting priority srcnat; policy accept; }'
nft add rule ip xsteer_nat post ip saddr ${HUB_SUBNET} oifname "${HUB_NIC}" masquerade
EOF
		chmod 0755 "$NATBIN"
		cat >"$NATUNIT" <<EOF
[Unit]
Description=xsteer — masquerade для трафика пиров
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$NATBIN
ExecStop=/usr/sbin/nft delete table ip xsteer_nat

[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		systemctl enable --now xsteer-nat >/dev/null 2>&1
	fi

	echo ""
	echo "Хаб настроен. Теперь первый пир — без него хаб не запустится: пиров нет."
	if ! newPeer; then
		echo -e "${RED}пир не добавлен${NC} — хаб остался ненастроенным."
		echo "Запустите скрипт снова: настройки уже сохранены, он предложит меню."
		exit 1
	fi

	echo ""
	printf "${GREEN}хаб работает${NC}: сеть туннеля %s\n" "${HUB_SUBNET}"
	case "$HUB_MODE" in
	1) echo "  поток (настоящий TCP) на ${HUB_PUB_IP}:${HUB_SPORT}" ;;
	2) echo "  поддельный TCP на ${HUB_PUB_IP}:${HUB_PORT}" ;;
	3) echo "  поддельный TCP на :${HUB_PORT}, поток на :${HUB_SPORT}" ;;
	esac
	echo ""
	echo "осталось сделать руками (это чужая конфигурация, установщик её не трогает):"
	echo "  1. открыть снаружи нужные порты TCP;"
	if [ "$HUB_MODE" != 1 ]; then
		echo "  2. НЕ поднимать на порту поддельного TCP ничего своего — он принадлежит хабу целиком."
	fi
	echo ""
	echo "состояние:  systemctl status xsteer-hub"
	echo "журнал:     journalctl -u xsteer-hub -f"
	echo "меню:       запустите этот скрипт снова"
}

# Применить конфигурацию: проверить, поднять юнит, убедиться, что работает.
#
# Одна функция на все пути — установка, добавление пира, удаление, — потому что порядок «проверить
# ДО перезапуска» обязателен в каждом из них, а забыть его легче всего в том, который добавили
# позже. Проверка идёт тем же кодом, что и запуск (xsteer check), иначе она однажды разойдётся с
# ним и скажет «годится» про файл, который хаб отвергнет.
function hubApply() {
	if ! "$BIN" check "$CONF" >/dev/null; then
		"$BIN" check "$CONF" 2>&1 | sed 's/^/  /'
		return 1
	fi
	systemctl daemon-reload
	systemctl enable --now xsteer-hub >/dev/null 2>&1
	systemctl restart xsteer-hub
	sleep 1
	if ! systemctl is-active --quiet xsteer-hub; then
		echo -e "${RED}хаб не запустился${NC}"
		journalctl -u xsteer-hub -n 20 --no-pager 2>/dev/null | sed 's/^/  /'
		return 1
	fi
	return 0
}

# ---- пиры --------------------------------------------------------------------

function nextFreeIP() {
	local i
	for i in $(seq 2 254); do
		grep -qE "^AllowedIPs[[:space:]]*=[[:space:]]*${HUB_BASE}\.${i}/32" "$CONF" || { echo "$i"; return 0; }
	done
	echo ""
}

function newPeer() {
	echo ""
	echo "Новый пир."
	echo "Имя — буквы, цифры, дефис и подчёркивание, до 15 символов."

	local exists=1
	until [[ ${PEER_NAME:-} =~ ^[a-zA-Z0-9_-]+$ ]] && [ "${#PEER_NAME}" -lt 16 ] && [ "$exists" = 0 ]; do
		ask PEER_NAME "Имя пира: "
		exists="$(grep -c "^### peer ${PEER_NAME}\$" "$CONF")"
		[ "$exists" != 0 ] && echo -e "${ORANGE}пир с таким именем уже есть${NC}"
	done

	local dot
	dot="$(nextFreeIP)"
	[ -n "$dot" ] || { echo "свободных адресов в ${HUB_SUBNET} не осталось"; unset PEER_NAME; return 1; }
	ask dot "Адрес пира в туннеле: ${HUB_BASE}." "$dot"
	local PEER_IP="${HUB_BASE}.${dot}"
	if grep -qE "^AllowedIPs[[:space:]]*=[[:space:]]*${PEER_IP}/32" "$CONF"; then
		echo -e "${ORANGE}этот адрес уже занят${NC}"; unset PEER_NAME; return 1
	fi

	# Сеть за пиром — это то, из-за чего иначе понадобится masquerade на самом пире. Перечислив её
	# здесь, хаб примет пакеты с адресами этой сети (иначе он отбросит их проверкой источника) и
	# сам поставит маршрут для ответов. Адреса при этом сохраняются — видно, кто ходил.
	echo ""
	echo "Сеть за этим пиром (его локальная сеть). Пусто — только адрес в туннеле;"
	echo "тогда на самом пире понадобится masquerade в туннель."
	local PEER_LAN=""
	ask PEER_LAN "Сеть за пиром, например 192.168.1.0/24: "
	if [ -n "$PEER_LAN" ]; then
		if ! [[ ${PEER_LAN} =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
			echo -e "${RED}не похоже на префикс${NC} — пропускаю"; PEER_LAN=""
		elif grep -q "${PEER_LAN}" "$CONF"; then
			# Пересечение AllowedIPs двух пиров разбор отвергает НАМЕРЕННО: на хабе
			# неоднозначность означает тихий увод трафика не туда.
			echo -e "${RED}эта сеть уже числится за другим пиром${NC} — пропускаю"; PEER_LAN=""
		fi
	fi

	echo ""
	echo "Что пир заворачивает в туннель:"
	echo "   1) только звезду (${HUB_SUBNET}) — интернет идёт напрямую"
	echo "   2) весь трафик (0.0.0.0/0) — интернет тоже через хаб"
	local WHAT
	until [[ ${WHAT:-} =~ ^[12]$ ]]; do ask WHAT "Выбор [1-2]: " 2; done
	local PEER_ALLOWED="${HUB_SUBNET}"
	[ "$WHAT" = 2 ] && PEER_ALLOWED="0.0.0.0/0"

	# Ключи делаются ЗДЕСЬ, как в wireguard-install, и это компромисс: приватный ключ пира проходит
	# через хаб. Аккуратнее — сделать пару на самом пире (`xsteer genkey`) и принести сюда только
	# публичную половину. Сказано прямо, чтобы выбор был осознанным, а не незамеченным.
	local ppriv ppub
	ppriv="$("$BIN" genkey)" || { echo "ключи не сделались"; unset PEER_NAME; return 1; }
	ppub="$(printf '%s\n' "$ppriv" | "$BIN" pubkey)" || { echo "ключи не сделались"; unset PEER_NAME; return 1; }

	local allowed="${PEER_IP}/32"
	[ -n "$PEER_LAN" ] && allowed="${PEER_IP}/32, ${PEER_LAN}"

	# Дописываем пира и ПРОВЕРЯЕМ конфигурацию до перезапуска: испорченный файл иначе уронил бы
	# работающий хаб вместе со всеми остальными пирами.
	cp "$CONF" "$CONF.bak"
	cat >>"$CONF" <<EOF

### peer ${PEER_NAME}
[Peer]
PublicKey  = ${ppub}
AllowedIPs = ${allowed}
EOF
	if ! hubApply; then
		echo -e "${RED}конфигурация с новым пиром не принята — возвращаю прежнюю${NC}"
		mv "$CONF.bak" "$CONF"
		hubApply >/dev/null 2>&1
		unset PEER_NAME
		return 1
	fi
	rm -f "$CONF.bak"

	# Порт и подсказки зависят от транспорта: пир на Windows ходит только потоком, и дать ему порт
	# поддельного TCP значило бы отдать конфигурацию, которая не подключится никогда.
	local ep_port="$HUB_PORT" note=""
	case "$HUB_MODE" in
	1) ep_port="$HUB_SPORT"; note="# Хаб поднят только в режиме потока: клиенту нужен ключ --stream (на Windows он включён сам)." ;;
	2) note="# Хаб поднят только на поддельном TCP: на Windows такой пир не заработает без драйвера-перехватчика." ;;
	3) note="# У хаба оба транспорта: этот порт — поддельный TCP. Для потока (и для Windows) возьмите порт ${HUB_SPORT} и ключ --stream." ;;
	esac

	local out="/root/xsteer-${PEER_NAME}.conf"
	( umask 077; cat >"$out" <<EOF
# Пир ${PEER_NAME} звезды xsteer.
# Положить в /etc/xsteer/${PEER_NAME}.conf и поднять: xs-quick up ${PEER_NAME}
${note}
[Interface]
PrivateKey = ${ppriv}
Address    = ${PEER_IP}/${HUB_PLEN}
# SNI: имя, которое уйдёт в ClientHello. Для наблюдателя поток выглядит обычным TLS к этому домену,
# поэтому имя стоит брать существующее и ничем не выделяющееся.
SNI        = www.microsoft.com

[Peer]
PublicKey  = ${HUB_PUB_KEY}
AllowedIPs = ${PEER_ALLOWED}
Endpoint   = ${HUB_PUB_IP}:${ep_port}
PersistentKeepalive = 25
EOF
	)

	# Ссылка xs:// — тот же доступ одной строкой. Рядом с файлом, а не вместо него: файл кладут в
	# /etc и им живёт служба, а ссылку удобно передать и превратить в QR-код.
	#
	# Пишется в ФАЙЛ с правами 0600, а не только на экран: в ссылке лежит приватный ключ, и её
	# место — там же, где конфигурация, а не в истории терминала. На экран она выводится тоже, но
	# отдельным шагом и с предупреждением — иначе смысл выдачи (передать доступ) требовал бы
	# лишних действий.
	local link="/root/xsteer-${PEER_NAME}.link"
	if ( umask 077; "$BIN" link "$out" --name "$PEER_NAME" >"$link" 2>/dev/null ); then
		:
	else
		rm -f "$link"; link=""
	fi

	echo ""
	printf "${GREEN}пир %s добавлен${NC}: %s, конфигурация в %s\n" "$PEER_NAME" "$PEER_IP" "$out"
	echo ""
	sed '/^PrivateKey/s/=.*/= <приватный ключ, он в файле>/' "$out"
	echo ""
	if [ -n "$link" ]; then
		printf "ссылка (тот же доступ одной строкой): %s\n" "$link"
		echo "  показать:  cat $link"
		echo "  QR-код:    qrencode -t ansiutf8 < $link"
		echo "  поднять:   xsteer up - < $link"
		printf "${RED}в ссылке приватный ключ — открытым каналом её пересылать нельзя${NC}\n"
		echo ""
	fi
	echo "MTU задавать НЕ НУЖНО: клиент согласует его сам и проверит путь пробами."
	unset PEER_NAME
}

function listPeers() {
	local n; n="$(grep -c "^### peer " "$CONF")"
	[ "$n" = 0 ] && { echo "пиров пока нет"; return 0; }
	echo "пиры (имя, что заворачивает):"
	awk '
		/^### peer /   { name = $3 }
		/^AllowedIPs/  { if (name != "") { sub(/^AllowedIPs[[:space:]]*=[[:space:]]*/, ""); print "  " name "  " $0; name = "" } }
	' "$CONF"
}

function revokePeer() {
	local n; n="$(grep -c "^### peer " "$CONF")"
	[ "$n" = 0 ] && { echo "пиров нет"; return 0; }
	echo "какого пира убрать?"
	grep "^### peer " "$CONF" | cut -d' ' -f3 | nl -s ') '
	local num=""
	until [[ ${num} =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le "$n" ]; do ask num "Номер [1-$n]: "; done
	local name; name="$(grep "^### peer " "$CONF" | cut -d' ' -f3 | sed -n "${num}p")"

	# Убираем блок пира целиком: метку, [Peer] и его ключи. Обрезать по счёту строк нельзя — у
	# пиров разное число полей.
	cp "$CONF" "$CONF.bak"
	awk -v target="$name" '
		/^### peer / { skip = ($3 == target); if (skip) next }
		skip && /^\[Peer\]|^PublicKey|^AllowedIPs|^PersistentKeepalive|^Endpoint|^[[:space:]]*$/ { next }
		skip         { skip = 0 }
		{ print }
	' "$CONF.bak" >"$CONF"

	if ! "$BIN" check "$CONF" >/dev/null 2>&1; then
		# Самый частый случай здесь — убирали последнего пира. Хабу нужен хотя бы один, поэтому это
		# не поломка, а осмысленный отказ, и сказать надо именно так.
		echo -e "${ORANGE}конфигурация без этого пира не проходит проверку — возвращаю прежнюю${NC}"
		echo "Если это был последний пир: хабу нужен хотя бы один. Чтобы выключить хаб целиком,"
		echo "выберите в меню «Снять хаб»."
		mv "$CONF.bak" "$CONF"
		return 1
	fi
	rm -f "$CONF.bak"
	hubApply || return 1
	rm -f "/root/xsteer-${name}.conf" "/root/xsteer-${name}.link"
	printf "${GREEN}пир %s убран${NC}\n" "$name"
	echo "На самом пире туннель после этого не поднимется: хаб его больше не знает."
}

function showStatus() {
	echo "юнит:"
	systemctl status xsteer-hub --no-pager -n 0 2>/dev/null | sed -n '1,4p'
	echo ""
	echo "устройство:"
	# Проверяется НЕПУСТОТА вывода, а не код возврата: за конвейером код принадлежит sed, который
	# на пустом входе успешен, и «устройства нет» превратилось бы в пустую строку.
	local dev_info; dev_info="$(ip -o addr show dev "${HUB_DEV}" 2>/dev/null)"
	if [ -n "$dev_info" ]; then echo "$dev_info" | sed 's/^/  /'
	else echo "  ${HUB_DEV} не создан — значит хаб не запускался или упал при старте"; fi
	echo ""
	echo "рукопожатия за сутки (по журналу):"
	local hist
	hist="$(journalctl -u xsteer-hub --since -1d --no-pager 2>/dev/null | grep -E "поднялся|согласован MTU" | tail -10)"
	if [ -n "$hist" ]; then echo "$hist" | sed 's/^/  /'
	else echo "  ни одного — проверьте, что порт открыт снаружи"; fi
	echo ""
	listPeers
	echo ""
	echo "полный журнал: journalctl -u xsteer-hub -f"
}

function uninstallHub() {
	echo ""
	ask yn "Точно снять хаб? Пиры останутся без связи. [y/n]: " n
	[[ ${yn} =~ ^[yY]$ ]] || return 0

	systemctl disable --now xsteer-hub >/dev/null 2>&1
	systemctl disable --now xsteer-nat >/dev/null 2>&1
	rm -f "$UNIT" "$NATUNIT" "$NATBIN" /etc/sysctl.d/99-xsteer.conf
	systemctl daemon-reload
	nft delete table ip xsteer_nat 2>/dev/null
	ip link del "${HUB_DEV}" 2>/dev/null

	# Ключи и конфигурации НЕ удаляются молча: восстановить их нельзя, а пиров без них пришлось бы
	# перевыпускать все до одного.
	echo ""
	echo "юнит, правило NAT и sysctl убраны."
	echo "Ключи и список пиров оставлены в $CONFDIR — удалите сами, если не нужны:"
	echo "  rm -rf $CONFDIR /root/xsteer-*.conf /root/xsteer-*.link $BIN"
}

function manageMenu() {
	echo "Хаб xsteer уже стоит."
	echo ""
	echo "Что делаем?"
	echo "   1) Добавить пира"
	echo "   2) Показать пиров"
	echo "   3) Убрать пира"
	echo "   4) Состояние"
	echo "   5) Снять хаб"
	echo "   6) Выход"
	local opt=""
	until [[ ${opt} =~ ^[1-6]$ ]]; do ask opt "Выбор [1-6]: "; done
	case "${opt}" in
	1) newPeer ;;
	2) listPeers ;;
	3) revokePeer ;;
	4) showStatus ;;
	5) uninstallHub ;;
	6) exit 0 ;;
	esac
}

initialCheck
if [ -e "$PARAMS" ]; then
	# shellcheck source=/dev/null
	source "$PARAMS"
	manageMenu
else
	installHub
fi
