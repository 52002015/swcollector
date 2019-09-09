package funcs

import (
	"time"

	"github.com/52002015/sw"
	"github.com/gaochao1/swcollector/g"
	"github.com/open-falcon/common/model"
)

type SwMgmtCpu struct {
	Ip      string
	CpuUtil int
}

func CpuMgmtMetrics() (L []*model.MetricValue) {

	chs := make([]chan SwMgmtCpu, len(AliveIp))
	for i, ip := range AliveIp {
		if ip != "" {
			chs[i] = make(chan SwMgmtCpu)
			go cpumgmtMetrics(ip, chs[i])
		}
	}

	for _, ch := range chs {
		swCpu, ok := <-ch
		if !ok {
			continue
		}
		L = append(L, GaugeValueIp(time.Now().Unix(), swCpu.Ip, "snmp.cpu.mgmt.utilization", swCpu.CpuUtil))
	}

	return L
}

func cpumgmtMetrics(ip string, ch chan SwMgmtCpu) {
	var swCpu SwMgmtCpu

	cpuUtili, err := sw.CpuMgmtUtilization(ip, g.Config().Switch.Community, g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
	if err != nil {
		close(ch)
		return
	}

	swCpu.Ip = ip
	swCpu.CpuUtil = cpuUtili
	ch <- swCpu

	return
}
