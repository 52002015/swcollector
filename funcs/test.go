package funcs

import (
	"log"
	"time"

	"github.com/52002015/sw"
	"github.com/gaochao1/swcollector/g"
	"github.com/open-falcon/common/model"
)

type SessionM struct {
	Ip           string
	sessionMetrics []SessionMetric
}
type SessionMetric struct {
	metric     string
	value      int
}

func SesMetrics() (L []*model.MetricValue) {
	chs := make([]chan SessionM, 0)
	for _, ip := range AliveIp {
		if ip != "" {
				chss := make(chan SessionM)
				go sessMetrics(ip, chss)
				chs = append(chs, chss)
		}
	}
	for _, ch := range chs {
		sessionm, ok := <-ch
		if !ok {
			continue
		}
		for _, sessionmetric := range sessionm.sessionMetrics {
			L = append(L, GaugeValueIp(time.Now().Unix(), sessionm.Ip, sessionmetric.metric, sessionmetric.value))
		}
	}
	return L
}

func sessMetrics(ip string, ch chan SessionM) {
	var sessionm SessionM
	var sessionmetrics []SessionMetric



	vendor, err := SysVendor(ip, community, g.Config().Switch.SnmpRetry, g.Config().Switch.SnmpTimeout)

	method := "get"

	switch vendor {
	case "PA_800", "PA":
		sessionmetrics := PaSession(ip)

	default:
		log.Println(ip)
		close(ch)
		return
	}


	sessionm.Ip = ip
	sessionm.sessionMetrics = sessionmetrics
	ch <- sessionm
	return
}

func PaSession(ip string) (sessionmetric SessionMetric){
	var sessionmetric SessionMetric
	var sessionmetrics []SessionMetric
 	ActiveTcp, err := GetMetric(ip, g.Config().Switch.Community, "1.3.6.1.4.1.25461.2.1.2.3.4.0", g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
 	if err == nil {
 		sessionmetric.metric = "snmp.session.panSessionActiveTcp"
 		sessionmetric.value = ActiveTcp
 		sessionmetrics = append(sessionmetrics, sessionmetric)
 	}
	ActiveUdp, err := GetMetric(ip, g.Config().Switch.Community, "1.3.6.1.4.1.25461.2.1.2.3.5.0", g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
	if err == nil {
                sessionmetric.metric = "snmp.session.panSessionActiveUdp"
                sessionmetric.value = ActiveUdp
                sessionmetrics = append(sessionmetrics, sessionmetric)
	}

	return sessionmetrics
}

func GetMetric(ip, community, oid string, timeout, retry int) (int, error) {
	defer func() {
		if r := recover(); r != nil {
			log.Println(ip+" Recovered in sessionMetric, Oid is ", oid, r)
		}
	}()
	method := "get"
	var value int
	var err error
	var snmpPDUs []go_snmp.SnmpPDU
	for i := 0; i < retry; i++ {
		snmpPDUs, err = sw.RunSnmp(ip, community, oid, method, timeout)
		if len(snmpPDUs) > 0 && err == nil {
			value, err = interfaceTofloat64(snmpPDUs[0].Value)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	return value, err
}
