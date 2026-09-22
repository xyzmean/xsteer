package xsteer

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/curve25519"

	"github.com/xyzmean/xsteer/client"
	"github.com/xyzmean/xsteer/conf"
	"github.com/xyzmean/xsteer/tun"
	"github.com/xyzmean/xsteer/wire"
)

// Logger — куда уходит журнал клиента. Реализуется на стороне платформы.
//
// Зовётся ИЗ РАЗНЫХ ГОРУТИН без всякой синхронизации с нашей стороны: подъём, слежение за сетью
// и каждое соединение пишут в журнал одновременно. Реализация обязана быть потокобезопасной.
type Logger interface {
	Log(line string)
}

// version — версия половины на Go. Подставляется при сборке ключом -X; без него честно говорит,
// что это сборка из дерева, а не выпуск.
var version = "из дерева"

// Version — версия половины на Go, для окна «о приложении».
func Version() string { return version }

// MaxMTU — самый большой MTU, который туннель готов нести.
//
// Ставить в настройках расширения больше НЕЛЬЗЯ, и это не предпочтение. Путь данных читает
// пакеты окнами ровно такого размера и признака усечения не имеет: пакет крупнее будет выброшен
// целиком (см. Device.Read и счётчик Oversize). Снаружи это выглядело бы как «мелкое ходит,
// крупное пропадает» — класс отказа, который дороже всего искать.
const MaxMTU = wire.MTUDefault

// Tunnel — поднятый или готовый к подъёму клиент.
//
// Один на процесс расширения: больше одного туннеля система одновременно и не поднимает.
type Tunnel struct {
	mu   sync.Mutex
	cfg  *conf.Conf
	sec  *conf.Secrets
	name string

	streamPort int
	logger     Logger

	// dev — устройство, каким его видит клиент: закрыть его надо в любом случае.
	// pkt — то же устройство, но когда оно наше, с очередью и вызовами. На Android его нет:
	// там дескриптор, и пакеты в него не кладут, а пишут. Два поля, а не утверждение типа,
	// потому что «если это вдруг наше» — ровно тот вопрос, который лучше задать один раз при
	// подъёме, чем на каждый пакет.
	dev    tun.Device
	pkt    *Device
	cli    *client.Client
	cancel context.CancelFunc
	done   chan struct{}
	runErr error
}

// NewTunnel создаёт пустой туннель. Дальше обязателен Configure.
func NewTunnel() *Tunnel { return &Tunnel{} }

// SetLogger задаёт получателя журнала. Можно до Configure.
func (t *Tunnel) SetLogger(l Logger) {
	t.mu.Lock()
	t.logger = l
	t.mu.Unlock()
}

// SetStreamPort задаёт порт хаба для режима потока. Ноль означает порт из Endpoint.
func (t *Tunnel) SetStreamPort(p int) {
	t.mu.Lock()
	t.streamPort = p
	t.mu.Unlock()
}

// Configure разбирает настройку: либо текст в виде файла (разделы Interface и Peer), либо одну
// строку xs://. Возвращает отказ с объяснением и номером строки — тем же, что видит человек в
// консольной половине.
//
// Ничего не трогает на диске: разбор целиком в памяти (conf.Parse), а не conf.Load. В песочнице
// приложения это не только удобнее, но и единственный работающий путь — conf.Load отвергает
// файл, доступный на чтение группе и остальным, а файлы в контейнере приложения именно такие.
func (t *Tunnel) Configure(text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return fmt.Errorf("настройка пуста")
	}
	// Имя хаба разрешается ЗАРАНЕЕ: движок принимает в Endpoint только литерал IPv4, а человек
	// почти всегда пишет имя. Разбор имени — дело платформы и сети, а не формата настройки,
	// поэтому он и стоит здесь, до conf.Parse, а не внутри него.
	resolved, err := resolveEndpoints(text)
	if err != nil {
		return err
	}
	var cfg *conf.Conf
	var sec *conf.Secrets
	var name string
	if conf.IsLink(resolved) {
		cfg, sec, name, err = conf.ParseLink(resolved, conf.RoleSpoke)
	} else {
		cfg, sec, err = conf.Parse([]byte(resolved), conf.RoleSpoke)
	}
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.cfg, t.sec, t.name = cfg, sec, name
	t.mu.Unlock()
	return nil
}

// ConfText — разобранная настройка обратно текстом, в том же виде, в каком её читает консольная
// половина.
//
// ЗАЧЕМ ЭТО НУЖНО. Ссылку xs:// разбирает только движок, и разбирать её второй раз на Kotlin или
// Swift значило бы иметь два мнения о формате. Приложение вместо этого просит движок превратить
// ссылку в текст: Configure принимает оба вида, ConfText возвращает всегда текст, и дальше с ним
// работает обычный разбор приложения.
//
// В тексте ЛЕЖИТ ПРИВАТНЫЙ КЛЮЧ — иначе это была бы не настройка. Место ему там же, где остальной
// настройке приложения, и никуда больше он копироваться не должен.
func (t *Tunnel) ConfText() (string, error) {
	t.mu.Lock()
	cfg, sec := t.cfg, t.sec
	t.mu.Unlock()
	if cfg == nil || sec == nil {
		return "", fmt.Errorf("настройка ещё не разобрана")
	}
	return conf.Render(cfg, sec)
}

// Name — имя из фрагмента ссылки xs://, если оно там было. Для заголовка в списке.
func (t *Tunnel) Name() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.name
}

// Address — свой адрес внутри туннеля. Для NEPacketTunnelNetworkSettings.
func (t *Tunnel) Address() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cfg == nil {
		return ""
	}
	return ip4(t.cfg.Addr)
}

// Netmask — маска своего адреса, в виде 255.255.255.0. Настройкам системы нужна именно она, а
// не длина префикса.
func (t *Tunnel) Netmask() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cfg == nil {
		return ""
	}
	if t.cfg.AddrPlen == 0 {
		return "0.0.0.0"
	}
	return ip4(^uint32(0) << (32 - uint(t.cfg.AddrPlen)))
}

// PrefixLen — длина префикса своего адреса.
//
// Рядом с Netmask, а не вместо неё, потому что двум системам нужно разное: настройкам iOS —
// маска в виде 255.255.255.0, построителю туннеля на Android — число. Переводить одно в другое
// на стороне платформы значило бы написать этот перевод дважды, на двух языках.
func (t *Tunnel) PrefixLen() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cfg == nil {
		return 0
	}
	return t.cfg.AddrPlen
}

// MTU — что ставить туннелю в настройках системы. Никогда не больше MaxMTU; почему — см. MaxMTU.
func (t *Tunnel) MTU() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	m := MaxMTU
	if t.cfg != nil && t.cfg.MTU > 0 && t.cfg.MTU < m {
		m = t.cfg.MTU
	}
	return m
}

// IncludedRoutes — что заворачивать в туннель: AllowedIPs хаба, через запятую, в виде
// 10.0.0.0/24. Пустая строка означает, что настройка ещё не разобрана.
//
// Строкой, а не срезом: gomobile срезов кроме []byte не переносит.
func (t *Tunnel) IncludedRoutes() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cfg == nil || len(t.cfg.Peers) == 0 {
		return ""
	}
	out := make([]string, 0, len(t.cfg.Peers[0].Allowed))
	for _, a := range t.cfg.Peers[0].Allowed {
		out = append(out, fmt.Sprintf("%s/%d", ip4(a.Net), a.Plen))
	}
	return strings.Join(out, ",")
}

// DNSServers — адреса резолверов из настройки, через запятую. Пусто означает «не трогать».
func (t *Tunnel) DNSServers() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cfg == nil {
		return ""
	}
	return strings.Join(t.cfg.DNS, ",")
}

// HubAddress и HubPort — куда пойдёт соединение. Нужны затем, чтобы адрес хаба можно было
// показать человеку и, если понадобится, исключить из маршрутов туннеля.
func (t *Tunnel) HubAddress() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cfg == nil || len(t.cfg.Peers) == 0 {
		return ""
	}
	return t.cfg.Peers[0].Endpoint
}

func (t *Tunnel) HubPort() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cfg == nil || len(t.cfg.Peers) == 0 {
		return 0
	}
	if t.streamPort > 0 {
		return t.streamPort
	}
	return t.cfg.Peers[0].EndpointPort
}

// Start поднимает туннель. Не блокирует: клиент работает в своей горутине до Stop.
//
// devName попадает только в журнал и в снимок состояния; осмысленно передать сюда имя, которое
// система дала своему интерфейсу.
func (t *Tunnel) Start(sink PacketSink, devName string) error {
	if sink == nil {
		return fmt.Errorf("нет получателя пакетов")
	}
	return t.start(func(mtu int) (tun.Device, error) {
		d := NewDevice(devName, sink, mtu)
		t.pkt = d
		return d, nil
	})
}

// StartFD поднимает туннель на ГОТОВОМ дескрипторе, который открыла система.
//
// Так работает Android: приложение просит VpnService, обратно получает открытый дескриптор и
// отдаёт его сюда. Это дешевле пути с вызовами — пакеты не пересекают границу языков вовсе, их
// читает и пишет тот же код, что на обычном Linux.
//
// Дескриптор переходит НАМ, и Stop его закроет. Поэтому отдавать надо detachFd(), а не getFd():
// иначе дескриптор закроют дважды, и второй раз попадёт в чужой, переиспользованный номер — а
// проявится это не здесь и не сразу.
func (t *Tunnel) StartFD(fd int, devName string) error {
	if fd < 0 {
		return fmt.Errorf("дескриптор не задан")
	}
	return t.start(func(mtu int) (tun.Device, error) {
		return newFDDevice(fd, devName, mtu)
	})
}

// start — общая часть обоих входов. Два способа заполучить устройство отличаются только им
// самим; всё остальное — настройки клиента, режим потока, слежение за сетью — обязано у них
// совпадать, и совпадает оно потому, что написано здесь один раз.
func (t *Tunnel) start(makeDev func(mtu int) (tun.Device, error)) error {
	t.mu.Lock()
	if t.cancel != nil {
		t.mu.Unlock()
		return fmt.Errorf("туннель уже поднят")
	}
	if t.cfg == nil || t.sec == nil {
		t.mu.Unlock()
		return fmt.Errorf("настройка не задана: сначала Configure")
	}
	mtu := MaxMTU
	if t.cfg.MTU > 0 && t.cfg.MTU < mtu {
		mtu = t.cfg.MTU
	}
	dev, err := makeDev(mtu)
	if err != nil {
		t.mu.Unlock()
		return err
	}
	lg := t.logger
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.dev, t.cancel, t.done, t.runErr = dev, cancel, done, nil

	opt := client.Options{
		Conf: t.cfg,
		Sec:  t.sec,
		// Устройство отдаётся готовым: своего открыть на iOS нельзя, /dev/net/tun там нет.
		Devs: []tun.Device{dev},
		// Одна очередь — одно соединение. Больше смысла не имеет: пакеты и туда, и оттуда идут
		// через один объект системы, и разводить их по нескольким соединениям значило бы только
		// переставлять их порядок.
		Conns: 1,
		// Адрес, MTU, маршруты и резолвер ставит система через NEPacketTunnelNetworkSettings.
		// Без этого клиент попытался бы сделать это сам и упал бы на первом же вызове.
		Managed: true,
		Routes:  false,
		// Единственный работающий транспорт: поддельный TCP требует сырого сокета, а его в
		// песочнице iOS нет и не будет. Не настройка, а следствие платформы.
		Stream:     true,
		StreamPort: t.streamPort,
		// Своё слежение за сетью здесь вредно: оно опрашивает адрес выхода раз в пять секунд, а
		// внутри расширения адресом источника ядро может назвать адрес самого туннеля — и опрос
		// решал бы, что сеть сменилась, каждые пять секунд. Двигать поколение обязана платформа
		// через NetChanged, у неё для этого есть NWPathMonitor.
		NoNetWatch: true,
		// На arm64 у Apple шифрование AES аппаратное на всех устройствах, где работает iOS 16.
		AESPreferred: true,
		StatePath:    "",
		Ready: func(c *client.Client) {
			t.mu.Lock()
			t.cli = c
			t.mu.Unlock()
		},
	}
	if lg != nil {
		opt.Logf = func(f string, a ...any) { lg.Log(fmt.Sprintf(f, a...)) }
	}
	t.mu.Unlock()

	go func() {
		err := client.Run(ctx, opt)
		t.mu.Lock()
		t.runErr = err
		t.cli = nil
		t.mu.Unlock()
		if lg != nil && err != nil && ctx.Err() == nil {
			lg.Log("туннель остановился: " + err.Error())
		}
		close(done)
	}()
	return nil
}

// Stop останавливает туннель и ждёт, пока клиент уйдёт.
//
// Ждать обязательно: клиент отдаёт накопленное и закрывает устройство в отсрочке до трёх секунд,
// а расширение, вернувшееся из stopTunnel раньше, получит от системы принудительное убийство
// процесса посреди этой уборки.
func (t *Tunnel) Stop() {
	t.mu.Lock()
	cancel, done, dev := t.cancel, t.done, t.dev
	t.cancel, t.done, t.dev, t.pkt = nil, nil, nil, nil
	t.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	if dev != nil {
		dev.Close()
	}
	if done != nil {
		<-done
	}
}

// Inject кладёт пакет от системы в туннель. Зовётся на каждый пакет из readPackets.
func (t *Tunnel) Inject(p []byte) {
	t.mu.Lock()
	dev := t.pkt
	t.mu.Unlock()
	if dev != nil {
		dev.Inject(p)
	}
}

// NetChanged говорит клиенту, что сеть под ним сменилась: все соединения надо переподнять, не
// дожидаясь таймаутов. Зовётся из NWPathMonitor и из sleep/wake.
func (t *Tunnel) NetChanged() {
	t.mu.Lock()
	cli := t.cli
	t.mu.Unlock()
	if cli != nil {
		cli.NetChanged()
	}
}

// StateJSON — снимок состояния в виде JSON. Секретов в нём нет ни одного: собирается из
// счётчиков и из разобранной настройки, до приватного ключа отсюда не дотянуться.
//
// Плюс два наших счётчика, которых у клиента нет: сколько пакетов от системы не влезло в очередь
// и сколько выброшено как слишком крупные. Второе — единственный признак расхождения MTU.
func (t *Tunnel) StateJSON() string {
	t.mu.Lock()
	cli, dev := t.cli, t.pkt
	t.mu.Unlock()
	out := map[string]any{"schema": 1, "up": false}
	if cli != nil {
		st := cli.StateNow()
		b, err := json.Marshal(st)
		if err == nil {
			_ = json.Unmarshal(b, &out)
		}
	}
	if dev != nil {
		out["queue_dropped"] = dev.Dropped()
		out["oversize_dropped"] = dev.Oversize()
	}
	b, err := json.Marshal(out)
	if err != nil {
		return `{"schema":1,"up":false}`
	}
	return string(b)
}

// ---- ключи --------------------------------------------------------------------
//
// Генерации пары в пакете conf нет — она живёт в консольной половине, и повторить её здесь
// дешевле, чем тащить зависимость от cmd. Формат тот же: 32 байта в base64, ровно 44 символа.

// Keys — пара ключей для той стороны, что на Swift.
//
// ПОЧЕМУ ТИПОМ, А НЕ ФУНКЦИЯМИ УРОВНЯ ПАКЕТА. Функция Go, возвращающая (string, error),
// выносится gomobile в функцию C с выходным параметром и признаком успеха, а не в метод с
// NSError, — и Swift такую как throws не видит: она у него просто не находится по имени.
// Методы связанного типа выносятся методами Objective-C с NSError**, а их Swift превращает в
// throws сам. Поэтому наружу отдаётся тип, а функции ниже остаются для Go и тестов.
type Keys struct {
	priv string
	pub  string
}

// NewKeys создаёт пустую пару. Дальше Generate или DeriveFrom.
func NewKeys() *Keys { return &Keys{} }

// Generate делает новую пару.
func (k *Keys) Generate() error {
	priv, err := GenerateKey()
	if err != nil {
		return err
	}
	pub, err := PublicKeyOf(priv)
	if err != nil {
		return err
	}
	k.priv, k.pub = priv, pub
	return nil
}

// DeriveFrom выводит публичный ключ из готового приватного. Отказ означает, что приватный
// ключ записан неверно, — тем же текстом, что в консольной половине.
func (k *Keys) DeriveFrom(priv string) error {
	pub, err := PublicKeyOf(priv)
	if err != nil {
		return err
	}
	k.priv, k.pub = priv, pub
	return nil
}

// Названия НЕ Private и Public нарочно: и то, и другое — ключевые слова Swift, и обращение к
// ним потребовало бы обратных кавычек. Имя, которое на другой стороне надо экранировать, — плохое
// имя.
func (k *Keys) PrivateKey() string { return k.priv }
func (k *Keys) PublicKey() string  { return k.pub }

// GenerateKey создаёт приватный ключ.
func GenerateKey() (string, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return "", err
	}
	// Приведение по RFC 7748: младшие три бита нулевые, старший бит снят, следующий выставлен.
	// Без него у одного секрета оказалось бы несколько написаний, и сравнение ключей перестало
	// бы значить сравнение доступа.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	return conf.KeyEncode(priv), nil
}

// PublicKeyOf выводит публичный ключ из приватного.
func PublicKeyOf(privB64 string) (string, error) {
	priv, err := conf.KeyDecode(privB64)
	if err != nil {
		return "", err
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	var out [32]byte
	copy(out[:], pub)
	return conf.KeyEncode(out), nil
}

// ---- вспомогательное ----------------------------------------------------------

func ip4(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// resolveEndpoints подставляет адрес вместо имени хаба.
//
// Движок принимает в Endpoint только литерал IPv4 — нарочно: разбор имени это сеть и время, а
// формат настройки обязан разбираться без того и другого. Но человек пишет имя, и разрешать его
// кому-то надо; здесь для этого самое место — до проверок формата и там, где сеть уже есть.
//
// Подстановка НЕ БЕЗУСЛОВНАЯ: литерал остаётся литералом, так что обычный случай эта правка
// строки не задевает вовсе, и повторный вызов ничего не меняет.
func resolveEndpoints(text string) (string, error) {
	if conf.IsLink(text) {
		return resolveInLink(text)
	}
	lines := strings.Split(text, "\n")
	for i, ln := range lines {
		eq := strings.IndexByte(ln, '=')
		if eq < 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(ln[:eq]), "Endpoint") {
			continue
		}
		val := strings.TrimSpace(ln[eq+1:])
		host, port, err := splitHostPort(val)
		if err != nil {
			continue // пусть о неправильном значении скажет conf.Parse, с номером строки
		}
		ip, err := resolve4(host)
		if err != nil {
			return "", err
		}
		if ip == host {
			continue
		}
		lines[i] = ln[:eq+1] + " " + net.JoinHostPort(ip, port)
	}
	return strings.Join(lines, "\n"), nil
}

// resolveInLink правит хост в ссылке xs://<ключ>@<хост>:<порт>?…
func resolveInLink(s string) (string, error) {
	at := strings.LastIndexByte(s, '@')
	if at < 0 {
		return s, nil
	}
	rest := s[at+1:]
	end := len(rest)
	if k := strings.IndexAny(rest, "?#/"); k >= 0 {
		end = k
	}
	host, port, err := splitHostPort(rest[:end])
	if err != nil {
		return s, nil // о неправильной ссылке скажет conf.ParseLink
	}
	ip, err := resolve4(host)
	if err != nil {
		return "", err
	}
	if ip == host {
		return s, nil
	}
	return s[:at+1] + net.JoinHostPort(ip, port) + rest[end:], nil
}

func splitHostPort(v string) (string, string, error) {
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return "", "", err
	}
	if host == "" || port == "" {
		return "", "", fmt.Errorf("пусто")
	}
	return host, port, nil
}

// resolve4 возвращает адрес IPv4 для имени. Литерал возвращается как есть.
func resolve4(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil {
			return "", fmt.Errorf("адрес хаба %s — IPv6, а движок несёт только IPv4", host)
		}
		return host, nil
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return "", fmt.Errorf("имя хаба %s не разрешилось: %w", host, err)
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
			return ip.To4().String(), nil
		}
	}
	return "", fmt.Errorf("у имени хаба %s нет адреса IPv4", host)
}
