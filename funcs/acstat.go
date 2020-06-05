package funcs

import (
	"log"
	"sync"

	"github.com/gaochao1/swcollector/g"
	"github.com/open-falcon/common/model"

	"time"

	"github.com/52002015/sw"
	"github.com/toolkits/slice"
)

type ChAcStat struct {
	Ip          string
	PingResult  bool
	UseTime     int64
	AcStatsList *[]sw.AcIfStats
}

type LastacMap struct {
	lock   *sync.RWMutex
	acstat map[string]*[]sw.AcIfStats
}

func NewLastacMap() {
	lastacmap = &LastacMap{
		lock:   new(sync.RWMutex),
		acstat: make(map[string]*[]sw.AcIfStats),
	}
}

func (m *LastacMap) Get(k string) *[]sw.AcIfStats {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if val, ok := m.acstat[k]; ok {
		return val
	}
	return nil
}

func (m *LastacMap) Set(k string, v *[]sw.AcIfStats) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.acstat[k] = v
	return
}

func (m *LastacMap) Check(k string) bool {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if _, ok := m.acstat[k]; !ok {
		return false
	}
	return true
}

var (
	AcAliveIp []string
	lastacmap *LastacMap
)

func AllAcIp() (allIp []string) {
	acIp := g.Config().Switch.IpRange

	if len(acIp) > 0 {
		for _, wip := range acIp {
			aip := sw.ParseIp(wip)
			for _, ip := range aip {
				//This is the more delegate way
				vender, _ := sw.SysVendor(ip, community, snmpRetry, snmpTimeout)
				if vender == "AC" {
					allIp = append(allIp, ip)
				}
			}
		}
	}
	return allIp
}

func AcMetrcis() (L []*model.MetricValue) {
	if g.Config().Switch.Enabled && len(g.Config().Switch.IpRange) > 0 {
		return acMetrics()
	}
	return
}

func acMetrics() (L []*model.MetricValue) {
	if g.ReloadType() {
		g.ParseConfig(g.ConfigFile)
		if g.Config().SwitchHosts.Enabled {
			hostcfg := g.Config().SwitchHosts.Hosts
			g.ParseHostConfig(hostcfg)
		}
		//		if g.Config().CustomMetrics.Enabled {
		//			custMetrics := g.Config().CustomMetrics.Template
		//			g.ParseCustConfig(custMetrics)
		//		}
		AcAliveIp = nil
	}
	initVariable()
	allIp := AllAcIp()
	timeout := time.Duration(g.Config().Transfer.Interval) * time.Second

	chs := make([]chan ChAcStat, len(allIp))
	limitCh := make(chan bool, g.Config().Switch.LimitConcur)
	startTime := time.Now()
	log.Printf("UpdateAcStats start. The number of concurrent limited to %d. IP addresses number is %d", g.Config().Switch.LimitConcur, len(allIp))
	if gosnmp {
		log.Println("get snmp message by gosnmp")
	} else {
		log.Println("get snmp message by snmpwalk")
	}
	for i, ip := range allIp {
		chs[i] = make(chan ChAcStat)
		limitCh <- true
		go coreAcMetrcis(ip, chs[i], limitCh)
		time.Sleep(5 * time.Millisecond)
	}
	for i, ch := range chs {
		select {
		case chAcStat, ok := <-ch:
			if !ok {
				continue
			}

			if chAcStat.PingResult == true && !slice.ContainsString(AcAliveIp, chAcStat.Ip) {
				AcAliveIp = append(AcAliveIp, chAcStat.Ip)
			}
			if chAcStat.AcStatsList != nil {
				if g.Config().Debug {
					log.Println("IP:", chAcStat.Ip, "PingResult:", chAcStat.PingResult, "len_list:", len(*chAcStat.AcStatsList), "UsedTime:", chAcStat.UseTime)
				}

				for _, acStat := range *chAcStat.AcStatsList {
					acNameTag := "acIfName=" + acStat.AcIfName
					//	apIndexTag := "apIndex=" + acStat.ApIndex
					ip := chAcStat.Ip
					AcIfOperStatus := 0
					if acStat.AcIfOperStatus == "yes" {
						AcIfOperStatus = 1
					}
					L = append(L, GaugeValueIp(acStat.TS, ip, "snmp.ac.AcIfOperStatus", AcIfOperStatus, acNameTag))
					L = append(L, GaugeValueIp(acStat.TS, ip, "snmp.ac.AcIfHCInOctets", acStat.AcIfHCInOctets, acNameTag))
					L = append(L, GaugeValueIp(acStat.TS, ip, "snmp.ac.AcIfHCOutOctets", acStat.AcIfHCOutOctets, acNameTag))
				}
				lastacmap.Set(chAcStat.Ip, chAcStat.AcStatsList)
			}
		case <-time.After(timeout):
			log.Println(allIp[i] + " go runtime timeout")
		}
	}

	endTime := time.Now()
	log.Printf("UpdateAcStats complete. Process time %s. Number of active ip is %d", endTime.Sub(startTime), len(AcAliveIp))

	if g.Config().Debug {
		for i, v := range AcAliveIp {
			log.Println("AcAliveIp:", i, v)
		}
	}

	return
}

//func pingCheck(ip string) bool {
//	var pingResult bool
//	for i := 0; i < pingRetry; i++ {
//		pingResult = sw.Ping(ip, pingTimeout, fastPingMode)
//		if pingResult == true {
//			break
//		}
//	}
//	return pingResult
//}

//func limitCheck(value float64, limit float64) bool {
//	if value < 0 {
//		return false
//	}
//	if limit > 0 {
//		if value > limit {
//			return false
//		}
//	}
//	return true
//}

func coreAcMetrcis(ip string, ch chan ChAcStat, limitCh chan bool) {
	var startTime, endTime int64
	startTime = time.Now().Unix()

	var chAcStat ChAcStat

	pingResult := pingCheck(ip)

	chAcStat.Ip = ip
	chAcStat.PingResult = pingResult

	if !pingResult {
		endTime = time.Now().Unix()
		chAcStat.UseTime = (endTime - startTime)
		<-limitCh
		ch <- chAcStat
		return
	} else {
		var acList []sw.AcIfStats
		var err error
		if gosnmp {
			acList, err = sw.ListAcIfStats(ip, community, snmpTimeout, ignoreIface, snmpRetry, limitCon, ignorePkt, ignoreOperStatus, ignoreBroadcastPkt, ignoreMulticastPkt, ignoreDiscards, ignoreErrors, ignoreUnknownProtos, ignoreOutQLen)
		}

		if err != nil {
			log.Printf(ip, err)
			close(ch)
		}

		if len(acList) > 0 {
			chAcStat.AcStatsList = &acList
		}

		endTime = time.Now().Unix()
		chAcStat.UseTime = (endTime - startTime)
		<-limitCh
		ch <- chAcStat
		return
	}

	return
}
