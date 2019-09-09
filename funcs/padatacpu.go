package funcs

import (
	"log"
	"time"

	"github.com/52002015/sw"
	"github.com/gaochao1/swcollector/g"
	"github.com/open-falcon/common/model"
)

type SwDataCpu struct {
	Ip      string
	CpuUtil int
}

func CpuDataMetrics() (L []*model.MetricValue) {

	chs := make([]chan SwDataCpu, len(AliveIp))
	for i, ip := range AliveIp {
		if ip != "" {
			chs[i] = make(chan SwDataCpu)
			go cpudataMetrics(ip, chs[i])
		}
	}

	for _, ch := range chs {
		swCpu, ok := <-ch
		if !ok {
			continue
		}
		L = append(L, GaugeValueIp(time.Now().Unix(), swCpu.Ip, "snmp.cpu.data.utilization", swCpu.CpuUtil))
	}

	return L
}

func cpudataMetrics(ip string, ch chan SwDataCpu) {
	var swCpu SwDataCpu

	cpuUtili, err := sw.CpuDataUtilization(ip, g.Config().Switch.Community, g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
	if err != nil {
		log.Println(err)
		close(ch)
		return
	}

	swCpu.Ip = ip
	swCpu.CpuUtil = cpuUtili
	ch <- swCpu

	return
}
