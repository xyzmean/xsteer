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
const Version = "0.1.0"

func usage() {
	fmt.Fprintf(os.Stderr, `xsteer %s — клиент своего VPN-протокола с обликом TLS

    xsteer up <файл.conf> [ключи]   поднять туннель (сторона, которая соединяется)
    xsteer hub <файл.conf> [ключи]   поднять хаб (сторона, которая слушает)
    xsteer genkey                    приватный ключ в base64 (на диск не пишет)
    xsteer pubkey                    публичный ключ из приватного на входе
    xsteer show [файл состояния]     что происходит с туннелем
    xsteer version                   версия и накладные расходы протокола

Ключи для up:
    --dev <имя>       имя устройства (по умолчанию xs0)
    --conns <N>       соединений к хабу (по умолчанию по одному на ядро, не больше %d)
    --state <путь>    писать состояние в JSON
    --routes          направить AllowedIPs хаба в устройство
    --managed         устройство настраивает кто-то другой: не трогать адрес и MTU
    --probe-ms <N>    как часто перепроверять путь (по умолчанию %d)
    --chacha          заставить ChaCha20-Poly1305 (по умолчанию решает наличие AES в процессоре)

Ключи для hub:
    --dev <имя>       имя устройства (по умолчанию %s)
    --workers <N>     воркеров (по умолчанию по числу ядер, не больше %d)
    --no-tun          не поднимать устройство: только трафик пир↔пир
    --decoy <режим>   что отвечать НЕОПОЗНАННЫМ: alert (по умолчанию), silent, reset
                      или proxy — отдавать соединение настоящему серверу
    --decoy-dest <host:port>   куда отдавать в режиме proxy
    --decoy-sni <список>       через запятую: какие имена из SNI разрешено пересылать
                               (точка в начале разрешает поддомены: .example.com)

Примеры:
    sudo xsteer up /etc/xsteer/hub.conf --routes
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
	opt := client.Options{AESPreferred: aesPreferred()}
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
		case "--managed":
			opt.Managed = true
		case "--chacha":
			forceChaCha = true
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
