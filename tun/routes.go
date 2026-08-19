package tun

import (
	"net/netip"
	"strings"
)

// endpointCovered — накрывает ли хоть один из маршрутов AllowedIPs адрес какой-либо конечной
// точки (адреса хаба). Если да, то без отдельного обхода собственный трафик клиента к хабу уйдёт
// в туннель — а туннель в этот момент ещё не поднят, и это видно как «dial tcp …: i/o timeout».
//
// Здесь оно НЕ под тегом windows и не трогает системных вызовов нарочно: это чистая арифметика над
// префиксами, её проверяет стенд на любой системе, а решение о закреплении /32 к endpoint (как в
// WireGuard) слишком дорого ошибиться, чтобы оставлять его без проверки.
func endpointCovered(cidrs, endpoints []string) bool {
	var addrs []netip.Addr
	for _, ep := range endpoints {
		if a, err := netip.ParseAddr(strings.TrimSpace(ep)); err == nil {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		return false
	}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(c))
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if p.Contains(a) {
				return true
			}
		}
	}
	return false
}
