//go:build !linux

package client

import (
	"context"
	"time"
)

// netQuiet и netPoll — те же сроки, что на Linux; смысл в комментарии netwatch_linux.go.
const (
	netQuiet = 250 * time.Millisecond
	netPoll  = 5 * time.Second
)

// watchNet на прочих системах работает ОПРОСОМ, без подписки на события.
//
// Подписка есть и здесь (на Windows это NotifyRouteChange2 и NotifyIpInterfaceChange, на macOS —
// сокет PF_ROUTE), но у неё своя обвязка на каждой системе, а выигрыш перед опросом — секунды. Опрос
// сам по себе стоит одного connect на UDP, то есть не отправляет ни одного пакета; поэтому здесь
// сначала работающий опрос, а подписка — отдельной работой, когда до этих систем дойдёт очередь.
func (c *Client) watchNet(ctx context.Context) {
	var have [4]byte
	var had bool
	if a, err := linkEgress(c.hub.addr); err == nil {
		have, had = a, true
	}
	t := time.NewTicker(netPoll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a, err := linkEgress(c.hub.addr)
		now, ok := a, err == nil
		if ok == had && now == have {
			continue
		}
		switch {
		case !ok:
			c.logf("сеть: пути к %s больше нет — жду, когда вернётся", c.hub.str)
		case !had:
			c.logf("сеть: путь к %s появился — поднимаю соединения сразу", c.hub.str)
		default:
			c.logf("сеть: адрес выхода к %s сменился — поднимаю соединения заново", c.hub.str)
		}
		have, had = now, ok
		c.bumpNet()
	}
}
