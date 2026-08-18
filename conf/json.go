package conf

import (
	"fmt"
	"strings"
)

func ip4(v uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// String печатает конфигурацию в JSON, без секретов.
//
// Метод объявлен на Conf, а не на паре (Conf, Secrets), и это то самое обещание из шапки
// пакета: дотянуться отсюда до приватного ключа нечем ПО ПОСТРОЕНИЮ. Тест закрепляет это
// поиском значения ключа из фикстуры в выводе — потому что «секретов нет» и «секретов не
// печатается» проверяются по-разному.
func (c *Conf) JSON() string {
	mtu := c.MTU
	if mtu == 0 {
		mtu = 1439 // тот же потолок, что wire.MTUDefault; печатаем «что будет», а не ноль
	}
	var b strings.Builder
	fmt.Fprintf(&b, `{"schema":1,"address":"%s/%d","mtu":%d,"peers":[`, ip4(c.Addr), c.AddrPlen, mtu)
	for i := range c.Peers {
		pe := &c.Peers[i]
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"key":"%s","keepalive":%d,"endpoint":`, KeyFP(pe.Pub), pe.Keepalive)
		if pe.EndpointPort != 0 {
			fmt.Fprintf(&b, `"%s:%d"`, pe.Endpoint, pe.EndpointPort)
		} else {
			b.WriteString("null")
		}
		b.WriteString(`,"allowed":[`)
		for a, al := range pe.Allowed {
			if a > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `"%s/%d"`, ip4(al.Net), al.Plen)
		}
		b.WriteString("]}")
	}
	b.WriteString("]}")
	return b.String()
}
