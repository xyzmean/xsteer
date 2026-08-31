// Клиент xsteer для настольных систем.
//
// Подкоманды названы так же, как в движке на C, там где они делают то же самое: человек, знающий
// роутерную половину, не должен учить второй набор слов. Разбор строгий — опечатка в флаге НЕ
// применяет команду молча, потому что «применилось не то, о чём просили» здесь означает туннель,
// который поднялся с чужой конфигурацией.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/cpu"

	"github.com/xyzmean/xsteer/client"
	"github.com/xyzmean/xsteer/conf"
	"github.com/xyzmean/xsteer/hub"
	"github.com/xyzmean/xsteer/wire"
)

// Version — версия клиента. Печатается при подъёме и в состоянии: две реализации одного протокола
// обязаны уметь назвать себя, иначе «у кого из них расхождение» выясняется догадками.
//
// ПЕРЕМЕННАЯ, А НЕ КОНСТАНТА, и это не стилистика. Релизный конвейер подставляет номер ключом
// -ldflags "-X main.Version=$VER", а -X умеет писать только в переменную: для константы
// линковщик молча ничего не делает. Пока здесь стоял const, все релизы печатали 0.1.0 — то есть
// ключ в workflow выглядел работающим и не работал, а узнать это можно было лишь запустив
// собранный файл.
var Version = "0.1.0"

func usage() {
	fmt.Fprintf(os.Stderr, `xsteer %s — клиент своего VPN-протокола с обликом TLS

    xsteer up <файл.conf> [ключи]   поднять туннель (сторона, которая соединяется)
    xsteer hub <файл.conf> [ключи]   поднять хаб (сторона, которая слушает)
    xsteer genkey                    приватный ключ в base64 (на диск не пишет)
    xsteer pubkey                    публичный ключ из приватного на входе
    xsteer check <файл.conf>         проверить конфигурацию, ничего не поднимая
    xsteer show [файл состояния]     что происходит с туннелем
    xsteer version                   версия и накладные расходы протокола

Ключи для up:
    --dev <имя>       имя устройства (по умолчанию xs0)
    --conns <N>       соединений к хабу (по умолчанию по одному на ядро, не больше %d)
    --state <путь>    писать состояние в JSON
    --routes          направить AllowedIPs хаба в устройство (по умолчанию ДА, как в WireGuard;
                      при 0.0.0.0/0 ставится полный туннель: расщепление маршрута и обход хаба)
    --no-routes       НЕ трогать маршруты: их ставит кто-то другой
    --managed         устройство настраивает кто-то другой: не трогать адрес, MTU и маршруты
    --probe-ms <N>    как часто перепроверять путь (по умолчанию %d)
    --chacha          заставить ChaCha20-Poly1305 (по умолчанию решает наличие AES в процессоре)
    --no-offload      не включать разгрузку сегментации устройства (для разбирательства)
    --no-batch        не собирать кадры в одну запись: нужно для разговора с хабом на C,
                      пока перенос не сделан. Облик на проводе при этом хуже
    --stream          вести записи по НАСТОЯЩЕМУ TCP вместо поддельного: без сырого сокета и
                      без прав на него. На Windows включён ВСЕГДА (поддельный TCP там
                      невозможен без драйвера); цена — TCP внутри TCP
    --no-stream       выключить режим потока там, где он включён по умолчанию
    --stream-port <N> порт хаба для режима потока (по умолчанию порт из Endpoint)
    --kill-switch     не возвращать маршрут по умолчанию, если туннель перестал нести трафик.
                      Без ключа сеть возвращается физическому интерфейсу (связь важнее);
                      с ключом трафик не пойдёт вовсе, но и наружу открытым не выйдет

Ключи для hub:
    --dev <имя>       имя устройства (по умолчанию %s)
    --workers <N>     воркеров (по умолчанию по числу ядер, не больше %d)
    --no-tun          не поднимать устройство: только трафик пир↔пир
    --no-offload      не включать разгрузку сегментации устройства (для разбирательства)
    --no-batch        не собирать кадры в одну запись: для клиента на C
    --stream-port <N> слушать НАСТОЯЩИЙ TCP на этом порту (режим потока), помимо поддельного
    --stream-only     не поднимать поддельный TCP вовсе: порт занимает только поток
    --decoy <режим>   что отвечать НЕОПОЗНАННЫМ: alert (по умолчанию), silent, reset
                      или proxy — отдавать соединение настоящему серверу
    --decoy-dest <host:port>   куда отдавать в режиме proxy
    --decoy-sni <список>       через запятую: какие имена из SNI разрешено пересылать
                               (точка в начале разрешает поддомены: .example.com)

Примеры:
    sudo xsteer up /etc/xsteer/hub.conf
    sudo xsteer hub /etc/xsteer/hub.conf --decoy proxy --decoy-dest www.microsoft.com:443
`, Version, wire.ConnsMax, wire.ProbeEveryMS, hub.Device, hub.WorkersMax)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "up":
		err = cmdUp(os.Args[2:])
	case "hub":
		err = cmdHub(os.Args[2:])
	case "genkey":
		err = cmdGenkey()
	case "pubkey":
		err = cmdPubkey()
	case "show":
		err = cmdShow(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "version":
		fmt.Printf("xsteer %s (Go %s, %s/%s)\n", Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		fmt.Printf("накладные расходы %d байт на пакет, MTU туннеля при канале 1500 — %d\n",
			wire.Overhead, wire.MTUDefault)
		fmt.Printf("шифр по умолчанию: %s\n", cipherName())
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "xsteer: неизвестная команда %q (подсказка: xsteer --help)\n", os.Args[1])
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "xsteer: %v\n", err)
		os.Exit(1)
	}
}

// aesPreferred — есть ли у процессора инструкции AES.
//
// Вопрос не праздный: он решает, какой шифр будет согласован с хабом, а разница между AES-GCM и
// ChaCha20-Poly1305 на процессоре БЕЗ этих инструкций — разы, и не в пользу AES. На настольных
// системах ответ почти всегда «есть», но спрашивать всё равно надо: тот же двоичный файл запускают
// и на маленькой машине без них.
func aesPreferred() bool {
	switch runtime.GOARCH {
	case "amd64", "386":
		return cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	case "arm64":
		return cpu.ARM64.HasAES
	case "arm":
		return cpu.ARM.HasAES
	}
	return false
}

func cipherName() string {
	if aesPreferred() {
		return "AES-128-GCM (в процессоре есть AES)"
	}
	return "ChaCha20-Poly1305 (аппаратного AES нет)"
}

func cmdUp(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("нужен путь к файлу конфигурации (подсказка: xsteer --help)")
	}
	path := args[0]
	// Routes включены по умолчанию: как в WireGuard, AllowedIPs означает «направь это в
	// туннель». Раньше без ключа --routes конфигурация с `AllowedIPs = 0.0.0.0/0` молча ни на
	// что не влияла — интерфейс поднимался, а трафик шёл мимо, и это выглядело как «туннель
	// есть, а через него ничего не идёт». Выключается явно: --no-routes или --managed (там
	// устройством и маршрутами распоряжается кто-то другой).
	// На Windows поток — ЕДИНСТВЕННЫЙ рабочий транспорт, и он включён по умолчанию.
	//
	// Отправка TCP через сырой сокет запрещена системой с XP SP2, поэтому без --stream клиент
	// поднимал устройство, ставил маршруты и не мог отправить ни одного пакета. Требовать ключ,
	// без которого на этой системе ничего не работает, — это ловушка, а не настройка: человек
	// получал молчащий туннель и никакого указания на причину.
	opt := client.Options{AESPreferred: aesPreferred(), Routes: true,
		Stream: runtime.GOOS == "windows"}
	forceChaCha := false
	// Разбор строгий и без библиотеки flag: она принимает `-conns=2` и `--conns 2` одинаково, но
	// молча съедает неизвестный ключ после первого позиционного аргумента. Здесь опечатка в ключе
	// — отказ, потому что «поднялось не то, о чём просили» означает туннель с чужой настройкой.
	for i := 1; i < len(args); i++ {
		key := args[i]
		value := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		switch key {
		case "--dev":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --dev нет значения")
			}
			opt.Device = v
		case "--conns":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --conns нет значения")
			}
			if _, err := fmt.Sscanf(v, "%d", &opt.Conns); err != nil || opt.Conns < 1 {
				return fmt.Errorf("--conns: нужно число не меньше 1, а не %q", v)
			}
		case "--state":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --state нет значения")
			}
			opt.StatePath = v
		case "--probe-ms":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --probe-ms нет значения")
			}
			var ms int
			if _, err := fmt.Sscanf(v, "%d", &ms); err != nil || ms < 1000 {
				return fmt.Errorf("--probe-ms: нужно число не меньше 1000, а не %q", v)
			}
			opt.ProbeEvery = time.Duration(ms) * time.Millisecond
		case "--routes":
			opt.Routes = true
		case "--no-routes":
			opt.Routes = false
		case "--managed":
			opt.Managed = true
			opt.Routes = false
		case "--chacha":
			forceChaCha = true
		case "--no-batch":
			opt.NoBatch = true
		case "--no-offload":
			opt.NoOffload = true
		case "--stream":
			opt.Stream = true
		case "--no-stream":
			opt.Stream = false
		case "--kill-switch":
			opt.KillSwitch = true
		case "--stream-port":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --stream-port нет значения")
			}
			if _, err := fmt.Sscanf(v, "%d", &opt.StreamPort); err != nil || opt.StreamPort < 1 {
				return fmt.Errorf("--stream-port: нужен порт, а не %q", v)
			}
			opt.Stream = true
		default:
			return fmt.Errorf("неизвестный ключ %s (подсказка: xsteer --help)", key)
		}
	}
	if forceChaCha {
		opt.AESPreferred = false
	}

	c, s, err := conf.Load(path, conf.RoleSpoke)
	if err != nil {
		return err
	}
	// Приватный ключ живёт в памяти столько, сколько живёт туннель, и затирается при уходе. Это не
	// защита от чтения памяти привилегированным процессом — от неё в пользовательской программе
	// защиты нет вовсе, — а гарантия того, что ключ не останется в куче после остановки.
	defer s.Wipe()
	opt.Conf, opt.Sec = c, s

	fmt.Fprintf(os.Stderr, "xsteer %s: %s, накладные %d байт\n", Version, cipherName(), wire.Overhead)

	// Ctrl-C и SIGTERM снимают туннель по-настоящему: снимается правило против RST, закрывается
	// устройство, состояние дописывается как «не работает». Без этого после остановки оставался бы
	// хвост в nftables и файл состояния, врущий «up».
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Крестик на окне консоли Windows сигналом не является: без этого обработчика за нами
	// остались бы маршрут по умолчанию в мёртвом туннеле и обход /32 на физическом интерфейсе.
	done := make(chan struct{})
	installConsoleHandler(stop, done)
	defer close(done)
	if err := client.Run(ctx, opt); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func cmdHub(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("нужен путь к файлу конфигурации хаба (подсказка: xsteer --help)")
	}
	path := args[0]
	opt := hub.Options{}
	for i := 1; i < len(args); i++ {
		key := args[i]
		value := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		switch key {
		case "--dev":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --dev нет значения")
			}
			opt.Device = v
		case "--workers":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --workers нет значения")
			}
			if _, err := fmt.Sscanf(v, "%d", &opt.Workers); err != nil || opt.Workers < 1 {
				return fmt.Errorf("--workers: нужно число не меньше 1, а не %q", v)
			}
		case "--no-tun":
			opt.NoTUN = true
		case "--stream-only":
			opt.StreamOnly = true
		case "--no-batch":
			opt.NoBatch = true
		case "--no-offload":
			opt.NoOffload = true
		case "--stream-port":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --stream-port нет значения")
			}
			if _, err := fmt.Sscanf(v, "%d", &opt.StreamPort); err != nil || opt.StreamPort < 1 {
				return fmt.Errorf("--stream-port: нужен порт, а не %q", v)
			}
		case "--decoy":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --decoy нет значения")
			}
			opt.Decoy.Mode = v
		case "--decoy-dest":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --decoy-dest нет значения")
			}
			opt.Decoy.Dest = v
		case "--decoy-sni":
			v, ok := value()
			if !ok {
				return fmt.Errorf("у ключа --decoy-sni нет значения")
			}
			opt.Decoy.FollowSNI = true
			for _, name := range strings.Split(v, ",") {
				if name = strings.TrimSpace(name); name != "" {
					opt.Decoy.Allow = append(opt.Decoy.Allow, name)
				}
			}
		default:
			return fmt.Errorf("неизвестный ключ %s (подсказка: xsteer --help)", key)
		}
	}
	// Настройка защиты проверяется ДО подъёма: неверная, обнаруженная в бою, — это защита, которой
	// нет, а узнать об этом пришлось бы от того, кто её обошёл.
	if err := opt.Decoy.Validate(); err != nil {
		return err
	}
	c, s, err := conf.Load(path, conf.RoleHub)
	if err != nil {
		return err
	}
	defer s.Wipe()
	opt.Conf, opt.Sec = c, s

	fmt.Fprintf(os.Stderr, "xsteer %s: хаб, %s\n", Version, cipherName())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := hub.Run(ctx, opt); err != nil && ctx.Err() == nil {
		return err
	}
	return nil
}

func cmdGenkey() error {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		// Отказ, а не «возьмём время как источник»: слабый ключ хуже отсутствующего, потому что
		// выглядит настоящим.
		return fmt.Errorf("нет источника случайности: %w", err)
	}
	// Приведение к виду, который ожидает X25519 (RFC 7748): те же три бита, что чистит wg genkey.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	fmt.Println(conf.KeyEncode(priv))
	return nil
}

func cmdPubkey() error {
	var line string
	if _, err := fmt.Scanln(&line); err != nil {
		return fmt.Errorf("на вход ожидается приватный ключ в base64")
	}
	priv, err := conf.KeyDecode(line)
	if err != nil {
		return err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return err
	}
	var out [32]byte
	copy(out[:], pub)
	fmt.Println(conf.KeyEncode(out))
	return nil
}

func cmdShow(args []string) error {
	path := filepath.Join(os.TempDir(), "xsteer.json")
	if len(args) > 0 {
		path = args[0]
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("нет файла состояния %s: запустите up с ключом --state", path)
	}
	var st client.State
	if err := json.Unmarshal(b, &st); err != nil {
		return fmt.Errorf("файл состояния не разбирается: %w", err)
	}
	up := "не работает"
	if st.Up {
		up = fmt.Sprintf("работает, соединений %d", st.Conns)
	}
	fmt.Printf("устройство %s: %s\n", st.Device, up)
	fmt.Printf("хаб %s (ключ %s), рукопожатие %d с назад\n", st.Hub, st.HubKey, st.HandshakeAge)
	fmt.Printf("MTU %d (подтверждено пробой пути: %d)\n", st.MTU, st.MTUConfirmed)
	fmt.Printf("отдано %d пакетов / %d байт, принято %d / %d, потеряно %d\n",
		st.TXPackets, st.TXBytes, st.RXPackets, st.RXBytes, st.Dropped)
	return nil
}

// cmdCheck — разобрать конфигурацию и ничего не поднимать.
//
// ЗАЧЕМ ОТДЕЛЬНАЯ КОМАНДА. Обвязка (xs-quick, xs-install) правит файл, который читает РАБОТАЮЩИЙ
// хаб или туннель, и обязана убедиться в годности файла ДО перезапуска: иначе одна опечатка в
// добавленном пире роняет хаб вместе со всеми остальными пирами, и узнаётся это по тишине.
// Проверять тем же кодом, что и запуск, — единственный способ не разойтись с ним: своя проверка в
// скрипте повторяла бы разбор и однажды повторила бы его неверно.
//
// Роль выводится из файла, а не спрашивается ключом: ListenPort без Endpoint бывает только у хаба,
// Endpoint — только у пира. Ошибиться тут человеку легко, а последствие — «проверено» для файла,
// который другая роль отвергнет.
func cmdCheck(args []string) error {
	if len(args) == 0 {
		return errors.New("нужен путь к файлу конфигурации")
	}
	path := args[0]
	// Пробуем обе роли: подходящая скажет, что это за файл. Порядок важен только для сообщения об
	// ошибке — её отдаём от той роли, которая по виду файла ожидалась.
	c, sec, errSpoke := conf.Load(path, conf.RoleSpoke)
	role := "пир"
	if errSpoke != nil {
		var errHub error
		c, sec, errHub = conf.Load(path, conf.RoleHub)
		if errHub != nil {
			// Какую ошибку показать: если есть ListenPort и нет Endpoint — это хаб, и человеку
			// нужна ошибка хаба, а не жалоба роли пира на отсутствие Endpoint.
			if looksLikeHub(path) {
				return errHub
			}
			return errSpoke
		}
		role = "хаб"
	}
	defer sec.Wipe()

	fmt.Printf("%s: %s, разбор прошёл\n", path, role)
	fmt.Printf("адрес в туннеле %s/%d", ip4str(c.Addr), c.AddrPlen)
	if c.MTU > 0 {
		fmt.Printf(", MTU задан %d", c.MTU)
	} else {
		fmt.Printf(", MTU выведет сам (потолок %d)", wire.MTUDefault)
	}
	if c.ListenPort > 0 {
		fmt.Printf(", слушает %d", c.ListenPort)
	}
	fmt.Println()
	if c.SNI != "" {
		fmt.Printf("SNI %s\n", c.SNI)
	}
	if len(c.DNS) > 0 {
		fmt.Printf("серверы имён: %s\n", strings.Join(c.DNS, ", "))
	}
	fmt.Printf("пиров %d:\n", len(c.Peers))
	for i := range c.Peers {
		p := &c.Peers[i]
		nets := make([]string, 0, len(p.Allowed))
		for _, a := range p.Allowed {
			nets = append(nets, fmt.Sprintf("%s/%d", ip4str(a.Net), a.Plen))
		}
		fmt.Printf("  %s  %s", conf.KeyFP(p.Pub), strings.Join(nets, ", "))
		if p.EndpointPort > 0 {
			fmt.Printf("  через %s:%d", p.Endpoint, p.EndpointPort)
		}
		if p.KeepaliveSet {
			fmt.Printf("  keepalive %d с", p.Keepalive)
		}
		fmt.Println()
	}
	return nil
}

// looksLikeHub — на что похож файл по виду: ListenPort без Endpoint бывает только у хаба. Нужно
// лишь для выбора того сообщения об ошибке, которое человеку пригодится.
func looksLikeHub(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	hasListen, hasEndpoint := false, false
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if i := strings.IndexByte(ln, '='); i > 0 {
			switch strings.ToLower(strings.TrimSpace(ln[:i])) {
			case "listenport":
				hasListen = true
			case "endpoint":
				hasEndpoint = true
			}
		}
	}
	return hasListen && !hasEndpoint
}

// ip4str — адрес из хостового порядка в точечную запись. Свой, потому что в client и hub он не
// экспортирован, а тащить ради четырёх строк лишнюю связь между пакетами незачем.
func ip4str(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
