package funcs

import (
	"time"

	"github.com/52002015/sw"
	"github.com/gaochao1/swcollector/g"
	"github.com/open-falcon/common/model"
)

type ApJoinNum struct {
	Ip      string
	CpuUtil int
}

func ApJoinMetrics() (L []*model.MetricValue) {

	chs := make([]chan ApJoinNum, len(AliveIp))
	for i, ip := range AliveIp {
		if ip != "" {
			chs[i] = make(chan ApJoinNum)
			go apjoinmetrics(ip, chs[i])
		}
	}

	for _, ch := range chs {
		apJoin, ok := <-ch
		if !ok {
			continue
		}
		L = append(L, GaugeValueIp(time.Now().Unix(), apJoin.Ip, "snmp.ap.joinStatus", apJoin.CpuUtil))
	}

	return L
}

func apjoinmetrics(ip string, ch chan ApJoinNum) {
	var apJoin ApJoinNum

	cpuUtili, err := sw.ApJoinStatus(ip, g.Config().Switch.Community, g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
	if err != nil {
		close(ch)
		return
	}

	apJoin.Ip = ip
	apJoin.CpuUtil = cpuUtili
	ch <- apJoin

	return
}
