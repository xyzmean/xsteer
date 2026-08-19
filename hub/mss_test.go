package hub

import (
	"encoding/binary"
	"testing"

	"github.com/xyzmean/xsteer/route"
)

// TestMinMTU — узкое место из двух согласованных размеров, с обработкой «ещё не согласован» (0).
func TestMinMTU(t *testing.T) {
	cases := []struct{ a, b, want int }{
		{1420, 1380, 1380}, // оба известны — берём меньший
		{1380, 1420, 1380}, // порядок не важен
		{0, 1380, 1380},    // отправитель ещё не назвал размер — клампим по получателю
		{1420, 0, 1420},    // и наоборот
		{0, 0, 0},          // ни один не известен — клампить не по чему
		{1300, 1300, 1300}, // равны (случай, когда узкое место сам хаб)
	}
	for _, c := range cases {
		if got := minMTU(c.a, c.b); got != c.want {
			t.Errorf("minMTU(%d, %d) = %d, ждали %d", c.a, c.b, got, c.want)
		}
	}
}

// synMSS собирает минимальный IPv4/TCP SYN с одной опцией MSS.
func synMSS(mss int) []byte {
	ip := make([]byte, 44) // 20 IP + 24 TCP (20 + опция MSS 4)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	ip[9] = 6 // TCP
	tcp := ip[20:]
	tcp[12] = 6 << 4 // смещение данных = 6 слов (24 байта)
	tcp[13] = 0x02   // SYN
	tcp[20] = 2      // kind = MSS
	tcp[21] = 4      // длина опции
	binary.BigEndian.PutUint16(tcp[22:24], uint16(mss))
	return ip
}

func mssOf(ip []byte) int {
	tcp := ip[20:]
	return int(binary.BigEndian.Uint16(tcp[22:24]))
}

// TestПирПирКлампПоМинимуму воспроизводит сценарий из задачи: пир1 с MTU 1420, пир2 с MTU 1380,
// хаб шире обоих. SYN в ЛЮБУЮ сторону обязан выйти с MSS по меньшему из двух тоннелей (1380),
// иначе обратный поток шлёт сегменты, не влезающие в тоннель отправителя, и они молча пропадают.
//
// Здесь проверяется именно то число, которое хаб подставит в route.MSSClamp: minMTU(from, dst).
func TestПирПирКлампПоМинимуму(t *testing.T) {
	const (
		mtu1420 = 1420 // пир 1
		mtu1380 = 1380 // пир 2
	)
	want := mtu1380 - 40 // MSS = MTU - 20 IP - 20 TCP

	// Направление пир1 → пир2: from = пир1 (1420), dst = пир2 (1380).
	syn := synMSS(1460)
	route.MSSClamp(syn, minMTU(mtu1420, mtu1380))
	if got := mssOf(syn); got != want {
		t.Fatalf("пир1→пир2: MSS %d, ждали %d (минимум тоннелей)", got, want)
	}

	// Обратное направление пир2 → пир1: from = пир2 (1380), dst = пир1 (1420). Тот же минимум.
	syn = synMSS(1460)
	route.MSSClamp(syn, minMTU(mtu1380, mtu1420))
	if got := mssOf(syn); got != want {
		t.Fatalf("пир2→пир1: MSS %d, ждали %d (минимум тоннелей)", got, want)
	}

	// Сценарий из вопроса дословно: хаб 1300 — узкое место. Согласование опускает обе сессии до
	// 1300, и минимум даёт 1300 в обе стороны.
	const mtuHub = 1300
	syn = synMSS(1460)
	route.MSSClamp(syn, minMTU(mtuHub, mtuHub))
	if got := mssOf(syn); got != mtuHub-40 {
		t.Fatalf("узкий хаб: MSS %d, ждали %d", got, mtuHub-40)
	}
}
