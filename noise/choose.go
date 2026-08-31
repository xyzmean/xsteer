package noise

// ВЫБОР ИСПОЛНИТЕЛЯ ШИФРА ЗАМЕРОМ, А НЕ ПРИЗНАКАМИ ПРОЦЕССОРА.
//
// Прежде шифр выбирался по флагу AES-NI: есть — берём AES-GCM, нет — ChaCha20-Poly1305. Правило
// разумное и почти всегда верное, но оно отвечает не на тот вопрос. Настоящий вопрос — «что на этой
// машине быстрее», а на него флаг процессора отвечает только пока исполнитель один. Как только
// исполнителей стало два (свой код и ядро, а через ядро — микросхема), правило перестаёт работать в
// обе стороны: у процессора без AES-NI может быть аппаратный AES в ядре, и тогда AES обгоняет
// ChaCha; а на x86 с AES-NI ядерный путь проигрывает своему из-за двух системных вызовов на пакет.
//
// Поэтому здесь замер. Он идёт на пакете рабочего размера, все доступные пары «шифр × исполнитель»
// в одном прогоне, и занимает десятки миллисекунд один раз при подъёме — то есть меньше, чем одно
// рукопожатие.
//
// ЧТО ЗАМЕР НЕ РЕШАЕТ, СКАЗАНО ПРЯМО. Он мерит один поток на спокойной машине. Аппаратный
// ускоритель в ядре один на все ядра, поэтому на четырёх занятых ядрах он может оказаться хуже
// четырёх программных потоков, каждый со своим процессором. Такое различить startup-замером нельзя;
// поэтому есть ключ --crypto, которым человек навязывает решение, и строка в журнале с числами,
// чтобы он знал, что навязывает.

import (
	"fmt"
	"sort"
	"time"
)

// Speed — сколько стоит один пакет у одной пары «шифр × исполнитель».
type Speed struct {
	Kind    AEAD
	Backend Backend
	// NsPerPkt — наносекунды на пакет. Ноль означает «не измерялось»: см. Err.
	NsPerPkt int64
	// Driver — имя драйвера ядра, если считает ядро. По нему видно, микросхема это или тот же
	// процессор.
	Driver string
	Err    string
}

// MeasurePkt — размер пакета, на котором меряем. Полноразмерный внутренний пакет при канале 1500:
// именно он определяет полосу, а мелкие определяют задержку, и на них разница между исполнителями
// теряется в накладных расходах.
const MeasurePkt = 1440

// Measure гоняет все доступные пары и возвращает числа. Порядок — от быстрого к медленному.
//
// probe — можно ли ТРОГАТЬ ядро по-настоящему. Ложь означает «спрашивай только о том, что уже
// доступно»: привязка сокета AF_ALG подгружает фронтенд algif_aead сама, а он в защищённых сборках
// выключен намеренно (CVE-2026-31431), и расширять поверхность атаки машины ради замера нельзя.
// Правду говорит только тот, кто попросил ядро прямо.
func Measure(probe bool) []Speed {
	var out []Speed
	for _, kind := range []AEAD{AEADAES128, AEADChaCha} {
		for _, b := range []Backend{BackendGo, BackendKernel} {
			sp := Speed{Kind: kind, Backend: b}
			if b == BackendKernel {
				sp.Driver = KernelDriver(kind)
				// Сверка с эталоном идёт ДО замера: движок, дающий другие байты, не должен попасть
				// в сравнение скоростей вовсе — иначе он мог бы его выиграть.
				if ok, why := KernelUsable(kind, probe); !ok {
					sp.Err = why
					out = append(out, sp)
					continue
				}
			}
			ns, err := timeOne(kind, b)
			if err != nil {
				sp.Err = err.Error()
			} else {
				sp.NsPerPkt = ns
			}
			out = append(out, sp)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		switch {
		case a.NsPerPkt == 0 && b.NsPerPkt == 0:
			return false
		case a.NsPerPkt == 0:
			return false
		case b.NsPerPkt == 0:
			return true
		}
		return a.NsPerPkt < b.NsPerPkt
	})
	return out
}

// timeOne — наносекунды на пакет у одной пары.
//
// Берётся МИНИМУМ из проходов, а не среднее: нас интересует, на что машина способна, а не сколько ей
// помешали. Среднее на занятой машине измеряет соседние процессы.
func timeOne(kind AEAD, b Backend) (int64, error) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i * 7)
	}
	var sl sealer
	var err error
	if b == BackendKernel {
		sl, err = newKernelSealer(kind, keyLen(kind, key))
	} else {
		sl, err = newGoSealer(kind, keyLen(kind, key))
	}
	if err != nil {
		return 0, err
	}
	defer sl.close()

	buf := make([]byte, MeasurePkt+sl.overhead())
	nonce := make([]byte, 12)
	aad := []byte{0x17, 0x03, 0x03, 0x05, 0xa0}
	// Разогрев: первая операция разворачивает таблицы, а у ядерной ещё и прогревает путь вызова.
	for i := 0; i < 3; i++ {
		if _, err := sl.seal(buf[:0], nonce, buf[:MeasurePkt], aad); err != nil {
			return 0, err
		}
	}
	const rounds = 5
	best := int64(0)
	for r := 0; r < rounds; r++ {
		// Число операций подбирается так, чтобы проход занял хотя бы 2 мс: иначе разрешения часов
		// не хватает, и на быстрой машине измерялся бы шум.
		n := 16
		for {
			t0 := time.Now()
			for i := 0; i < n; i++ {
				if _, err := sl.seal(buf[:0], nonce, buf[:MeasurePkt], aad); err != nil {
					return 0, err
				}
			}
			d := time.Since(t0)
			if d >= 2*time.Millisecond || n >= 1<<16 {
				per := d.Nanoseconds() / int64(n)
				if best == 0 || per < best {
					best = per
				}
				break
			}
			n *= 4
		}
	}
	return best, nil
}

func keyLen(kind AEAD, key []byte) []byte {
	if kind == AEADAES128 {
		return key[:16]
	}
	return key
}

// Choose измеряет и расставляет исполнителей: каждому шифру — свой, победивший на этой машине.
//
// Возвращает, оказался ли AES быстрее ChaCha: это и есть ответ на вопрос, который клиент раньше
// решал флагом процессора. Хаб этим значением не пользуется — шифр называет клиент, — но замер ему
// нужен так же: исполнителя для названного шифра выбирает он сам.
func Choose(logf func(string, ...any)) (aesFaster bool) {
	// probe == false: «авто» не трогает то, чего нет. См. Measure.
	sp := Measure(false)
	bestOf := map[AEAD]Speed{}
	for _, x := range sp {
		if x.NsPerPkt == 0 {
			continue
		}
		if cur, ok := bestOf[x.Kind]; !ok || x.NsPerPkt < cur.NsPerPkt {
			bestOf[x.Kind] = x
		}
	}
	for kind, x := range bestOf {
		chosen[slot(kind)].Store(int32(x.Backend))
	}
	if logf != nil {
		for _, x := range sp {
			logf("шифр: %s", x.Line())
		}
		for _, kind := range []AEAD{AEADAES128, AEADChaCha} {
			if x, ok := bestOf[kind]; ok {
				logf("шифр: %s считает %s", kind, backendWord(x.Backend, x.Driver))
			}
		}
	}
	a, okA := bestOf[AEADAES128]
	c, okC := bestOf[AEADChaCha]
	switch {
	case okA && okC:
		return a.NsPerPkt < c.NsPerPkt
	case okA:
		return true
	}
	return false
}

// Line — одна строка замера для журнала.
func (s Speed) Line() string {
	who := "go"
	if s.Backend == BackendKernel {
		who = "ядро"
		if s.Driver != "" {
			who += " (" + s.Driver + ")"
		}
	}
	if s.NsPerPkt == 0 {
		return fmt.Sprintf("%-18s %-34s недоступно: %s", s.Kind, who, s.Err)
	}
	mbits := float64(MeasurePkt) * 8 * 1e3 / float64(s.NsPerPkt)
	return fmt.Sprintf("%-18s %-34s %8d нс на пакет %d байт, %d Мбит/с на поток",
		s.Kind, who, s.NsPerPkt, MeasurePkt, int(mbits))
}

func backendWord(b Backend, driver string) string {
	if b != BackendKernel {
		return "свой код"
	}
	if driver == "" {
		return "ядро"
	}
	return "ядро, драйвер " + driver
}
