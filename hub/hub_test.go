package hub

import (
	"testing"

	"github.com/xyzmean/xsteer/conf"
	"github.com/xyzmean/xsteer/wire"
)

// TestЁмкостьТаблицыСессийНеЗависитОтЯдер: полная звезда обязана помещаться в таблицу сессий при
// ЛЮБОМ числе ядер.
//
// Предел держался константой «сессий на воркера», выведенной делением на WorkersMax — то есть на
// ПРЕДЕЛ числа воркеров, а не на факт. На одноядерной машине воркер один, и суммарная ёмкость
// выходила 64 против законных 128 (32 пира × 4 соединения): полная звезда физически не помещалась,
// а исчерпание таблицы в accept вытесняет чужую сессию — то есть звезда входила в цикл
// переподключений на ровном месте, и хуже всего именно на самом дешёвом VPS.
func TestЁмкостьТаблицыСессийНеЗависитОтЯдер(t *testing.T) {
	need := conf.PeersMax * wire.ConnsMax
	c := &conf.Conf{ListenPort: 443, Peers: make([]conf.Peer, conf.PeersMax)}

	was := numCPU
	defer func() { numCPU = was }()

	for _, cpus := range []int{1, 2, 3, 4, 8, 64} {
		numCPU = func() int { return cpus }
		n := workerCount(Options{Conf: c})
		total := n * sessPerWorker(n)
		if total < need {
			t.Errorf("при %d ядрах воркеров %d, ёмкость %d — законная звезда (%d сессий) не влезает",
				cpus, n, total, need)
		}
	}

	// И то же при явно заданном числе воркеров: оператор вправе поставить один воркер руками.
	for _, want := range []int{1, 2, 4} {
		n := workerCount(Options{Conf: c, Workers: want})
		if total := n * sessPerWorker(n); total < need {
			t.Errorf("--workers %d: воркеров %d, ёмкость %d, нужно не меньше %d",
				want, n, total, need)
		}
	}
}
