package hub

import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/xyzmean/xsteer/chello"
	"github.com/xyzmean/xsteer/link"
	"github.com/xyzmean/xsteer/noise"
	"github.com/xyzmean/xsteer/wire"
)

// Что делать с тем, кто постучался, но своим не оказался.
//
// ЗАЧЕМ ЗДЕСЬ ВЫБОР, А НЕ ОДНО ПОВЕДЕНИЕ. Активное зондирование — это прибор, который сам
// присылает настоящий ClientHello на наш порт и смотрит, что ответят. Ответ и есть отпечаток, и у
// каждого варианта своя цена:
//
//	alert  — фатальное оповещение TLS (handshake_failure). Так отвечает настоящий сервер, которому
//	         предложили то, чего он не может, — но НЕ так отвечает сервер, у которого есть
//	         сертификат для запрошенного имени. То есть отличимо: настоящий HTTPS на :443 после
//	         ClientHello присылает ServerHello и сертификат, а мы — семь байт отказа. Это поведение
//	         движка на C, и оно оставлено ради совместимости ожиданий, а не потому, что хорошо.
//	silent — не отвечать вовсе. Отличимо СИЛЬНЕЕ, чем оповещение: открытый порт, завершивший
//	         рукопожатие TCP и замолчавший на ClientHello, в интернете почти не встречается.
//	reset   — RST. Выглядит как «сервис упал между SYN и данными»; повторяемость выдаёт подделку
//	         сразу — настоящий сервер так себя не ведёт на каждом соединении.
//	proxy  — ОТДАТЬ соединение настоящему серверу. Прибор получает подлинный ServerHello,
//	         подлинный сертификат и подлинную страницу — то есть видит ровно то, что увидел бы на
//	         сайте-прикрытии. Это единственный вариант, который отвечает на зондирование не
//	         «признаком», а правдой.
//
// ПОЧЕМУ proxy ВОЗМОЖЕН ЗДЕСЬ, ХОТЯ В ПЛАНЕ ДВИЖКА НА C НАПИСАНО, ЧТО НЕТ. Там сказано:
// «проксирование требует настоящей точки TCP, а настоящий слушающий сокет на том же порту отвечал
// бы SYN-ACK нашим же пирам». Это верно про СЛУШАЮЩИЙ СОКЕТ ЯДРА — и неверно про нас: поддельным
// TCP владеем мы сами, в пользовательском пространстве, и никакого сокета ядра на порту нет. Значит
// мы можем сами открыть настоящее соединение к сайту-прикрытию и переливать байты в обе стороны
// через своё поддельное. Пир при этом не задет ничем: его сессия опознана раньше, чем начинается
// эта дорожка.
//
// ЧЕГО proxy НЕ ДАЁТ, СКАЗАНО ПРЯМО. Наш поддельный TCP не делает повторных передач: потерянный
// сегмент рукопожатия TLS означает для прибора зависшее соединение, а не «поддельный сервер». На
// обычном пути потерь нет, и прибор видит настоящий сайт; на пути с потерями он увидит обрыв —
// подозрительно, но неотличимо от плохой связи. Настоящая точка TCP в пользовательском пространстве
// (с окном и повторами) — отдельная работа, и её стоимость надо мерить, а не предполагать.
type DecoyMode struct {
	// Mode: "", "alert", "silent", "reset" или "proxy".
	Mode string
	// Dest — куда отдавать соединение в режиме proxy: "host:port". Пусто вместе с FollowSNI
	// означает, что режим proxy включить нельзя.
	Dest string
	// FollowSNI — соединяться с тем именем, которое назвал сам прибор, а не с постоянным Dest.
	//
	// Даёт правильный сертификат на ЛЮБОЕ запрошенное имя, то есть закрывает главную дырку
	// постоянного назначения: прибор просит SNI, которого мы не обслуживаем, получает сертификат
	// сайта-прикрытия и видит несовпадение. Цена — наш порт становится пересылкой к произвольному
	// узлу на :443, поэтому имена ограничены Allow.
	FollowSNI bool
	// Allow — какие имена разрешено пересылать при FollowSNI. Пусто означает «только Dest».
	Allow []string
	// Timeout — сколько ждать сайт-прикрытие. Ноль означает пять секунд.
	Timeout time.Duration
}

func (d DecoyMode) describe() string {
	switch d.Mode {
	case "silent":
		return "не отвечать (отличимо: открытый порт, замолчавший на ClientHello)"
	case "reset":
		return "RST"
	case "proxy":
		if d.FollowSNI {
			return fmt.Sprintf("отдавать настоящему серверу по имени из SNI (по умолчанию %s)", d.Dest)
		}
		return "отдавать настоящему серверу " + d.Dest
	default:
		return "фатальное оповещение TLS (отличимо от настоящего сервера с сертификатом)"
	}
}

// Validate проверяет настройку до подъёма хаба: неверная настройка защиты, обнаруженная в бою, —
// это защита, которой нет.
func (d DecoyMode) Validate() error {
	switch d.Mode {
	case "", "alert", "silent", "reset":
		return nil
	case "proxy":
		if d.Dest == "" {
			return fmt.Errorf("для режима proxy нужен адрес сайта-прикрытия")
		}
		if _, _, err := net.SplitHostPort(d.Dest); err != nil {
			return fmt.Errorf("адрес сайта-прикрытия должен быть вида host:port: %w", err)
		}
		return nil
	}
	return fmt.Errorf("неизвестный режим для неопознанных: %q (alert, silent, reset или proxy)", d.Mode)
}

// onStranger — единственная дорожка для тех, кто не наш. hsErr — почему не наш (nil означает
// «рукопожатие разобралось, но такого пира нет в конфигурации»).
//
// ВАЖНО, ЧТО ЭТА ДОРОЖКА ОДНА. Первая версия отвечала оповещением из двух разных мест (не разобрали
// Hello и не нашли пира), и они успели разойтись по поведению — а разница в ответе на два разных
// «не наш» это ровно то, что прибор и ищет: она рассказывает, ГДЕ мы его отвергли.
func (w *worker) onStranger(k skey, s *session, seg *link.Seg, hsErr error) {
	d := w.h.opt.Decoy
	switch d.Mode {
	case "silent":
		w.free(k, s)
		return
	case "reset":
		w.sendRST(seg)
		w.free(k, s)
		return
	case "proxy":
		if w.startProxy(k, s, seg) {
			return // сессия жива и переливает байты; освободит её сама дорожка
		}
		// Не удалось дозвониться до сайта-прикрытия — отвечаем как настоящий сервер, у которого
		// не сошлось: это хуже проксирования, но лучше молчания.
		fallthrough
	default:
		_ = s.conn.Send(link.PSH|link.ACK, noise.Alert())
		w.free(k, s)
	}
	_ = hsErr
}

// startProxy отдаёт соединение настоящему серверу и переливает байты в обе стороны.
//
// Возвращает true, если перелив начался: тогда сессию освобождает сама дорожка, а не вызывающий.
func (w *worker) startProxy(k skey, s *session, seg *link.Seg) bool {
	d := w.h.opt.Decoy
	dest := d.Dest
	// Имя из SNI — то, ради чего прибор и пришёл. Отдав ему сертификат другого сайта, мы сообщим
	// ровно то, что пытались скрыть.
	if d.FollowSNI {
		if ref, err := chello.Parse(seg.Payload); err == nil && ref.SNI != "" {
			if host := allowedHost(ref.SNI, d.Allow); host != "" {
				dest = net.JoinHostPort(host, "443")
			}
		}
	}
	if dest == "" {
		return false
	}
	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	up, err := net.DialTimeout("tcp", dest, timeout)
	if err != nil {
		if ok, held := w.rlProbe.Allow(nowMS(), wire.LogEveryMS); ok {
			w.h.logf("неопознанный с %s: сайт-прикрытие %s недоступен (%v)%s",
				ip4b(k.addr), dest, err, wire.HeldSuffix(held))
		}
		return false
	}
	if ok, held := w.rlProbe.Allow(nowMS(), wire.LogEveryMS); ok {
		w.h.logf("неопознанный с %s: отдаю настоящему серверу %s%s", ip4b(k.addr), dest,
			wire.HeldSuffix(held))
	}
	// Первым делом уходит ЕГО ClientHello — целиком и без правок. Любая правка означала бы, что
	// сайт-прикрытие видит не тот отпечаток, который прислал прибор, и ответил бы иначе, чем
	// ответил бы ему напрямую.
	hello := make([]byte, len(seg.Payload))
	copy(hello, seg.Payload)
	if _, err := up.Write(hello); err != nil {
		up.Close()
		return false
	}
	s.phase = phProxy
	s.up = up
	// Обратное направление: что ответил настоящий сервер — то и отдаём прибору через поддельное
	// соединение. Резать на сегменты обязательно: у нас датаграммная семантика, и сегмент больше
	// MSS просто не дойдёт.
	go w.proxyDown(k, s, up)
	return true
}

// proxyDown переливает ответ сайта-прикрытия прибору.
func (w *worker) proxyDown(k skey, s *session, up net.Conn) {
	defer up.Close()
	buf := make([]byte, 1200)
	_ = up.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		n, err := up.Read(buf)
		if n > 0 {
			// Отправка идёт через ту же неделимую операцию, что и данные пиров, только БЕЗ
			// шифрования: прибор говорит настоящий TLS с настоящим сервером, и наше дело —
			// перенести байты, а не подписать их.
			s.mu.Lock()
			alive := s.phase == phProxy
			s.mu.Unlock()
			if !alive {
				return
			}
			if err := s.conn.Send(link.PSH|link.ACK, buf[:n]); err != nil {
				return
			}
			_ = up.SetReadDeadline(time.Now().Add(30 * time.Second))
		}
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
	}
}

// proxyUp — то, что прибор присылает дальше, уходит настоящему серверу.
func (w *worker) proxyUp(k skey, s *session, seg *link.Seg) {
	if s.up == nil {
		w.free(k, s)
		return
	}
	if len(seg.Payload) == 0 {
		return
	}
	if _, err := s.up.Write(seg.Payload); err != nil {
		s.up.Close()
		w.free(k, s)
	}
}

// allowedHost — можно ли пересылать к этому имени.
//
// Список нужен не из осторожности: без него порт хаба становится открытой пересылкой на :443 к
// любому узлу, то есть чужим инструментом. Пустой список означает «только постоянное назначение».
func allowedHost(sni string, allow []string) string {
	sni = strings.ToLower(strings.TrimSuffix(sni, "."))
	if sni == "" || strings.ContainsAny(sni, "/\\ ") {
		return ""
	}
	for _, a := range allow {
		a = strings.ToLower(a)
		if a == sni {
			return sni
		}
		// Подстановка вида «.example.com» разрешает поддомены: сайты-прикрытия обычно живут
		// целыми доменами, и перечислять каждый узел вручную означало бы, что список не обновят.
		if strings.HasPrefix(a, ".") && strings.HasSuffix(sni, a) {
			return sni
		}
	}
	return ""
}
