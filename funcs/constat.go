package funcs

import (
	"time"

	"github.com/52002015/sw"
	"github.com/gaochao1/swcollector/g"
	"github.com/open-falcon/common/model"
)

type ConUseNum struct {
	Ip      string
	InUse int
}

func ConInUseMetrics() (L []*model.MetricValue) {

	chs := make([]chan ConUseNum, len(AliveIp))
	for i, ip := range AliveIp {
		if ip != "" {
			chs[i] = make(chan ConUseNum)
			go coninusemetrics(ip, chs[i])
		}
	}

	for _, ch := range chs {
		conIn, ok := <-ch
		if !ok {
			continue
		}
		L = append(L, GaugeValueIp(time.Now().Unix(), conIn.Ip, "snmp.connectionsInUse", conIn.InUse))
	}

	return L
}

func coninusemetrics(ip string, ch chan ConUseNum) {
	var conIn ConUseNum

	inUse, err := sw.ConInUseStatus(ip, g.Config().Switch.Community, g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
	if err != nil {
		close(ch)
		return
	}

	conIn.Ip = ip
	conIn.InUse = inUse
	ch <- conIn

	return
}
