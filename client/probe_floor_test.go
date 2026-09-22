package client

// Стенд итога пробоя пути, в котором не подтвердился ни один размер выше низа (I-278).

import (
	"testing"

	"github.com/xyzmean/xsteer/conf"
	"github.com/xyzmean/xsteer/wire"
)

// TestПробойНаНизуНазываетНизВсемСоединениям: повторный пробой под живой сессией (раз в
// ProbeEveryMS) не подтвердил ничего выше MTUFloor, и устройство ушло на низ. Нулевое соединение
// говорит об этом хабу своим кадром итога, но остальные называют хабу mtuPub — и если он остался
// прежним (1439), их сессии на хабе так и остаются на 1439: хаб режет по нему MSS обратного
// трафика и шлёт полноразмерные кадры в путь, который мы только что признали узким. Условие
// «назвать заново» у них — s.mtuTold != mtuPub, поэтому mtuPub обязан стать низом.
func TestПробойНаНизуНазываетНизВсемСоединениям(t *testing.T) {
	c := &Client{opt: Options{
		Conf: &conf.Conf{},
		Logf: func(f string, a ...any) { t.Logf("клиент: "+f, a...) },
	}}
	const was = 1439
	c.mtuNow.Store(was)
	c.mtuPub.Store(was)

	conn, raw := standConn(t)
	s := &sess{conn: conn, tx: standKeys(t), mtuConfirmed: was, mtuAgreed: wire.MTUDefault}
	s.pLo, s.pHi = wire.MTUFloor, was
	before := len(raw.sent)

	c.probeDone(s, 0, nopDev{}, "xstest0")

	if got := c.mtuNow.Load(); got != wire.MTUFloor {
		t.Fatalf("устройство на %d, ждали низ %d", got, wire.MTUFloor)
	}
	if len(raw.sent) == before {
		t.Error("нулевое соединение не сказало хабу про низ")
	}
	if got := int(c.mtuPub.Load()); got != wire.MTUFloor {
		t.Errorf("mtuPub остался %d после ухода на низ %d: соединения кроме нулевого не назовут "+
			"хабу новый размер, их сессии на хабе останутся на %d", got, wire.MTUFloor, got)
	}
	if st := c.Snapshot("xstest0"); st.MTUConfirmed != wire.MTUFloor {
		t.Errorf("состояние показывает подтверждённым %d, а путь подтвердил только %d",
			st.MTUConfirmed, wire.MTUFloor)
	}
}
