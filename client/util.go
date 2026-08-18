package client

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"context"

	"github.com/xyzmean/xsteer/conf"
)

func numCPU() int { return runtime.NumCPU() }

func parseIP4(s string) ([4]byte, error) {
	var out [4]byte
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return out, fmt.Errorf("адрес хаба не разобран: %s", s)
	}
	copy(out[:], ip.To4())
	return out, nil
}

func ip4str(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// State — снимок состояния для того, кто спросит: службы надзора, графического клиента, отладки.
//
// Секретов здесь нет ни одного, и это не обещание, а следствие: собирается снимок из счётчиков и
// из conf.Conf, до приватного ключа отсюда не дотянуться.
type State struct {
	Schema       int    `json:"schema"`
	Device       string `json:"device"`
	Up           bool   `json:"up"`
	Conns        int    `json:"conns"`
	MTU          int    `json:"mtu"`
	MTUConfirmed int    `json:"mtu_confirmed"`
	Hub          string `json:"hub"`
	HubKey       string `json:"hub_key"`
	HandshakeAge int64  `json:"handshake_age"`
	TXPackets    uint64 `json:"tx_packets"`
	TXBytes      uint64 `json:"tx_bytes"`
	RXPackets    uint64 `json:"rx_packets"`
	RXBytes      uint64 `json:"rx_bytes"`
	Dropped      uint64 `json:"dropped"`
}

// Snapshot собирает состояние. Счётчики читаются без общего замка: они только растут, и
// расхождение на несколько пакетов в снимке безвредно, а замок на пути, который ведёт счёт на
// каждый пакет, — нет.
func (c *Client) Snapshot(devName string) State {
	age := int64(-1)
	if hs := c.stats.lastHandshake.Load(); hs != 0 {
		age = time.Now().Unix() - hs
	}
	return State{
		Schema:       1,
		Device:       devName,
		Up:           c.stats.up.Load() > 0,
		Conns:        int(c.stats.up.Load()),
		MTU:          int(c.mtuNow.Load()),
		MTUConfirmed: int(c.mtuPub.Load()),
		Hub:          c.hub.str,
		HubKey:       conf.KeyFP(c.hub.pub),
		HandshakeAge: age,
		TXPackets:    c.stats.txPkts.Load(),
		TXBytes:      c.stats.txBytes.Load(),
		RXPackets:    c.stats.rxPkts.Load(),
		RXBytes:      c.stats.rxBytes.Load(),
		Dropped:      c.stats.dropped.Load(),
	}
}

// stateLoop пишет состояние в файл раз в две секунды.
//
// Через временный файл и переименование: читатель не должен увидеть половину файла. Это тот же
// приём и та же причина, что в движке на C, — состояние читают сторонние программы, и «иногда
// битый JSON» они переживают хуже, чем «немного устаревший».
func (c *Client) stateLoop(ctx context.Context, devName string) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	write := func() {
		b, err := json.Marshal(c.Snapshot(devName))
		if err != nil {
			return
		}
		tmp := c.opt.StatePath + ".tmp"
		if err := os.MkdirAll(filepath.Dir(c.opt.StatePath), 0o755); err != nil {
			return
		}
		if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
			return
		}
		_ = os.Rename(tmp, c.opt.StatePath)
	}
	for {
		write()
		select {
		case <-ctx.Done():
			// Последний снимок при уходе: иначе файл остался бы врать «up», пока его кто-нибудь не
			// перечитает.
			c.stats.up.Store(0)
			write()
			return
		case <-t.C:
		}
	}
}
