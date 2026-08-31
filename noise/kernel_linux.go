//go:build linux

package noise

// Тонкая прослойка между выбором движка (aead.go) и самим AF_ALG (alg_linux.go). Отдельным файлом,
// потому что на прочих системах она подменяется заглушкой: AF_ALG есть только у Linux.

// newKernelSealer — шифр, который считает ядро.
func newKernelSealer(kind AEAD, key []byte) (sealer, error) { return newAlgSealer(kind, key) }

// KernelUsable — можно ли доверить ядру этот шифр. Вторым значением — почему нет.
//
// probe == false означает «не трогать то, чего нет»: см. algLoaded. Так спрашивает режим «авто».
// probe == true пробует по-настоящему и потому может подгрузить фронтенд — так спрашивает явное
// --crypto kernel.
//
// Сверка с эталоном идёт ЗДЕСЬ, а не при первом пакете: движок, дающий другие байты, обязан быть
// отвергнут до того, как через него пойдёт трафик.
func KernelUsable(kind AEAD, probe bool) (bool, string) {
	if !probe && !algLoaded() {
		return false, "algif_aead не загружен, а грузить его сами мы не станем: он открывает " +
			"ядерную криптографию всем процессам и в защищённых сборках выключен намеренно " +
			"(CVE-2026-31431). Нужен ядерный шифр — попросите прямо: --crypto kernel"
	}
	if err := algProbe(kind); err != nil {
		return false, err.Error()
	}
	if err := algSelfTest(kind); err != nil {
		return false, "сверка с эталоном не сошлась: " + err.Error()
	}
	return true, ""
}

// KernelDriver — какой драйвер ядра стоит за шифром: имя вида «gcm(aes-eip93)» означает, что
// считает микросхема, а «gcm_base(ctr(aes-generic),ghash-generic)» — что тот же процессор.
//
// Нужно человеку, а не коду: «ядерная криптография включена» само по себе не говорит, стало ли
// лучше, — а имя драйвера говорит.
func KernelDriver(kind AEAD) string { return algDrivers(kind) }
