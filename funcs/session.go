package funcs

import (
	"log"
	"time"

	go_snmp "github.com/gaochao1/gosnmp"
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



	vendor, err := sw.SysVendor(ip, community, g.Config().Switch.SnmpRetry, g.Config().Switch.SnmpTimeout)
	if err != nil {
		log.Println(err)
		close(ch)
		return
	}

	switch vendor {
	case "PA_800", "PA":
		sessionmetrics = PaSession(ip)
	
	case "Cisco_ASA", "Cisco_ASA_OLD":
		sessionmetrics = AsaSession(ip)
	
	default:
		close(ch)
		return
	}


	sessionm.Ip = ip
	sessionm.sessionMetrics = sessionmetrics
	ch <- sessionm
	return
}

func PaSession(ip string) (sessionmetrics []SessionMetric){
	var sessionmetric SessionMetric
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
	Utilization, err := GetMetric(ip, g.Config().Switch.Community, "1.3.6.1.4.1.25461.2.1.2.3.1.0", g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
	if err == nil {
                sessionmetric.metric = "snmp.session.panSessionUtilization"
                sessionmetric.value = Utilization
                sessionmetrics = append(sessionmetrics, sessionmetric)
	}
	Active, err := GetMetric(ip, g.Config().Switch.Community, "1.3.6.1.4.1.25461.2.1.2.3.3.0", g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
	if err == nil {
                sessionmetric.metric = "snmp.session.panSessionActive"
                sessionmetric.value = Active
                sessionmetrics = append(sessionmetrics, sessionmetric)
	}

	return sessionmetrics
}

func AsaSession(ip string) (sessionmetrics []SessionMetric){
	var sessionmetric SessionMetric
 	l2l, err := GetMetric(ip, g.Config().Switch.Community, "1.3.6.1.4.1.9.9.392.1.3.29", g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
 	if err == nil {
 		sessionmetric.metric = "snmp.session.l2lNumSessions"
 		sessionmetric.value = l2l
 		sessionmetrics = append(sessionmetrics, sessionmetric)
 	}
	ipsec, err := GetMetric(ip, g.Config().Switch.Community, "1.3.6.1.4.1.9.9.392.1.3.26", g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
	if err == nil {
                sessionmetric.metric = "snmp.session.IPSecNumSessions"
                sessionmetric.value = ipsec
                sessionmetrics = append(sessionmetrics, sessionmetric)
	}
	svc, err := GetMetric(ip, g.Config().Switch.Community, "1.3.6.1.4.1.9.9.392.1.3.35", g.Config().Switch.SnmpTimeout, g.Config().Switch.SnmpRetry)
	if err == nil {
                sessionmetric.metric = "snmp.session.SVCNumSessions"
                sessionmetric.value = svc
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
		value = snmpPDUs[0].Value.(int)
		time.Sleep(100 * time.Millisecond)
	}
	return value, err
}
