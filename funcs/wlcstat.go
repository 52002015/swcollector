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

type ChWlcStat struct {
	Ip           string
	PingResult   bool
	UseTime      int64
	WlcStatsList *[]sw.WlcStats
}

type LastwlcMap struct {
	lock    *sync.RWMutex
	wlcstat map[string]*[]sw.WlcStats
}

func NewLastwlcMap() {
	lastwlcmap = &LastwlcMap{
		lock:    new(sync.RWMutex),
		wlcstat: make(map[string]*[]sw.WlcStats),
	}
}

func (m *LastwlcMap) Get(k string) *[]sw.WlcStats {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if val, ok := m.wlcstat[k]; ok {
		return val
	}
	return nil
}

func (m *LastwlcMap) Set(k string, v *[]sw.WlcStats) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.wlcstat[k] = v
	return
}

func (m *LastwlcMap) Check(k string) bool {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if _, ok := m.wlcstat[k]; !ok {
		return false
	}
	return true
}

//var (
//	WlcAliveIp             []string
//	pingTimeout         int
//	pingRetry           int
//	lastwlcmap           *LastwlcMap
//	community           string
//	snmpTimeout         int
//	snmpRetry           int
//	displayByBit        bool
//	gosnmp              bool
//	ignoreIface         []string
//	ignorePkt           bool
//	ignoreBroadcastPkt  bool
//	ignoreMulticastPkt  bool
//	ignoreDiscards      bool
//	ignoreErrors        bool
//	ignoreOperStatus    bool
//	ignoreUnknownProtos bool
//	ignoreOutQLen       bool
//	ignoreSpeedPercent  bool
//	fastPingMode        bool
//	limitCon            int
//)
var (
	WlcAliveIp []string
	lastwlcmap *LastwlcMap
)

// This init will be done in ifstat.go part
//func initVariable() {
//	pingTimeout = g.Config().Switch.PingTimeout
//	fastPingMode = g.Config().Switch.FastPingMode
//	pingRetry = g.Config().Switch.PingRetry

//	community = g.Config().Switch.Community
//	snmpTimeout = g.Config().Switch.SnmpTimeout
//	snmpRetry = g.Config().Switch.SnmpRetry
//	limitCon = g.Config().Switch.LimitCon

//	gosnmp = g.Config().Switch.Gosnmp
//	ignoreIface = g.Config().Switch.IgnoreIface
//	ignorePkt = g.Config().Switch.IgnorePkt
//	ignoreOperStatus = g.Config().Switch.IgnoreOperStatus
//	ignoreBroadcastPkt = g.Config().Switch.IgnoreBroadcastPkt
//	ignoreMulticastPkt = g.Config().Switch.IgnoreMulticastPkt
//	ignoreDiscards = g.Config().Switch.IgnoreDiscards
//	ignoreErrors = g.Config().Switch.IgnoreErrors
//	ignoreUnknownProtos = g.Config().Switch.IgnoreUnknownProtos
//	ignoreOutQLen = g.Config().Switch.IgnoreOutQLen
//}

func AllWlcIp() (allIp []string) {
	wlcIp := g.Config().Switch.IpRange

	if len(wlcIp) > 0 {
		for _, wip := range wlcIp {
			aip := sw.ParseIp(wip)
			for _, ip := range aip {
				//  this is a simple to way to filter wlc
				//ip_hostname := g.HostConfig().GetHostname(ip)
				//if strings.Contains(strings.ToLower(ip_hostname),"wlc") {
				//	allIp = append(allIp, ip)
				//}

				//This is the more delegate way
				vender, _ := sw.SysVendor(ip, community, snmpRetry, snmpTimeout)
				if vender == "Cisco_WLC" {
					allIp = append(allIp, ip)
				}
			}
		}
	}
	return allIp
}

func WlcMetrcis() (L []*model.MetricValue) {
	if g.Config().Switch.Enabled && len(g.Config().Switch.IpRange) > 0 {
		return wlcMetrics()
	}
	return
}

func wlcMetrics() (L []*model.MetricValue) {
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
		WlcAliveIp = nil
	}
	initVariable()
	ts := time.Now().Unix()
	allIp := AllWlcIp()
	timeout := time.Duration(g.Config().Transfer.Interval) * time.Second

	chs := make([]chan ChWlcStat, len(allIp))
	limitCh := make(chan bool, g.Config().Switch.LimitConcur)
	startTime := time.Now()
	log.Printf("UpdateWlcStats start. The number of concurrent limited to %d. IP addresses number is %d", g.Config().Switch.LimitConcur, len(allIp))
	if gosnmp {
		log.Println("get snmp message by gosnmp")
	} else {
		log.Println("get snmp message by snmpwalk")
	}
	for i, ip := range allIp {
		chs[i] = make(chan ChWlcStat)
		limitCh <- true
		go coreWlcMetrcis(ip, chs[i], limitCh)
		time.Sleep(5 * time.Millisecond)
	}
	for i, ch := range chs {
		select {
		case chWlcStat, ok := <-ch:
			if !ok {
				continue
			}

			if chWlcStat.PingResult == true && !slice.ContainsString(WlcAliveIp, chWlcStat.Ip) {
				WlcAliveIp = append(WlcAliveIp, chWlcStat.Ip)
			}
			if chWlcStat.WlcStatsList != nil {
				if g.Config().Debug {
					log.Println("IP:", chWlcStat.Ip, "PingResult:", chWlcStat.PingResult, "len_list:", len(*chWlcStat.WlcStatsList), "UsedTime:", chWlcStat.UseTime)
				}

				for _, wlcStat := range *chWlcStat.WlcStatsList {
					apNameTag := "apName=" + wlcStat.ApName
					//	apIndexTag := "apIndex=" + wlcStat.ApIndex
					ip := chWlcStat.Ip
					if wlcStat.ApName == "server" {
						apNameTag = ""
						L = append(L, GaugeValueIp(wlcStat.TS, ip, "snmp.HaPrimaryUnit", wlcStat.ApHaPrimaryUnit, apNameTag))
						L = append(L, GaugeValueIp(wlcStat.TS, ip, "snmp.RFStatusPeerUnitState", wlcStat.RFStatusPeerUnitState, apNameTag))
					}

					L = append(L, GaugeValueIp(wlcStat.TS, ip, "snmp.ap.PowerStatus", wlcStat.ApPowerStatus, apNameTag))
					L = append(L, GaugeValueIp(wlcStat.TS, ip, "snmp.ap.AssociatedClientCount", wlcStat.ApAssociatedClientCount, apNameTag))
					L = append(L, GaugeValueIp(wlcStat.TS, ip, "snmp.ap.MemoryCurrentUsage", wlcStat.ApMemoryCurrentUsage, apNameTag))
					L = append(L, GaugeValueIp(wlcStat.TS, ip, "snmp.ap.CpuCurrentUsage", wlcStat.ApCpuCurrentUsage, apNameTag))
					L = append(L, GaugeValueIp(wlcStat.TS, ip, "snmp.ap.ConnectCount", wlcStat.ApConnectCount, apNameTag))
					L = append(L, GaugeValueIp(wlcStat.TS, ip, "snmp.ap.UpTime", wlcStat.ApUpTime, apNameTag))

					if lastWlcStatList := lastwlcmap.Get(chWlcStat.Ip); lastWlcStatList != nil {
						for _, lastwlcStat := range *lastWlcStatList {
							if wlcStat.ApIndex == lastwlcStat.ApIndex {
								interval := wlcStat.TS - lastwlcStat.TS
								errorsPktlimit := g.Config().Switch.ErrorsPktlimit
								ApEthernetIfInputErrors := (float64(wlcStat.ApEthernetIfInputErrors) - float64(lastwlcStat.ApEthernetIfInputErrors)) / float64(interval)
								ApEthernetIfOutputErrors := (float64(wlcStat.ApEthernetIfOutputErrors) - float64(lastwlcStat.ApEthernetIfOutputErrors)) / float64(interval)
								ApReassocFailCount := (float64(wlcStat.ApReassocFailCount) - float64(lastwlcStat.ApReassocFailCount)) / float64(interval)
								ApAssocFailTimes := (float64(wlcStat.ApAssocFailTimes) - float64(lastwlcStat.ApAssocFailTimes)) / float64(interval)

								if limitCheck(ApEthernetIfInputErrors, errorsPktlimit) {
									L = append(L, GaugeValueIp(ts, ip, "snmp.ap.EthernetIfInputErrors", ApEthernetIfInputErrors, apNameTag))
								} else {
									log.Println(ip, apNameTag, "snmp.ap.EthernetIfInputErrors ", "out of range, value is ", ApEthernetIfInputErrors, "Limit is ", errorsPktlimit)
									log.Println("ApEthernetIfInputErrors This Time: ", wlcStat.ApEthernetIfInputErrors)
									log.Println("ApEthernetIfInputErrors Last Time: ", lastwlcStat.ApEthernetIfInputErrors)
								}
								L = append(L, GaugeValueIp(ts, ip, "snmp.ap.EthernetIfOutputErrors", ApEthernetIfOutputErrors, apNameTag))
								L = append(L, GaugeValueIp(ts, ip, "snmp.ap.ReassocFailCount", ApReassocFailCount, apNameTag))
								L = append(L, GaugeValueIp(ts, ip, "snmp.ap.AssocFailTimes", ApAssocFailTimes, apNameTag))
							}
						}
					}

				}
				lastwlcmap.Set(chWlcStat.Ip, chWlcStat.WlcStatsList)
			}
		case <-time.After(timeout):
			log.Println(allIp[i] + " go runtime timeout")
		}
	}

	endTime := time.Now()
	log.Printf("UpdateWlcStats complete. Process time %s. Number of active ip is %d", endTime.Sub(startTime), len(WlcAliveIp))

	if g.Config().Debug {
		for i, v := range WlcAliveIp {
			log.Println("WlcAliveIp:", i, v)
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

func coreWlcMetrcis(ip string, ch chan ChWlcStat, limitCh chan bool) {
	var startTime, endTime int64
	startTime = time.Now().Unix()

	var chWlcStat ChWlcStat

	pingResult := pingCheck(ip)

	chWlcStat.Ip = ip
	chWlcStat.PingResult = pingResult

	if !pingResult {
		endTime = time.Now().Unix()
		chWlcStat.UseTime = (endTime - startTime)
		<-limitCh
		ch <- chWlcStat
		return
	} else {
		var wlcList []sw.WlcStats
		var err error
		if gosnmp {
			wlcList, err = sw.ListWlcStats(ip, community, snmpTimeout, ignoreIface, snmpRetry, limitCon, ignorePkt, ignoreOperStatus, ignoreBroadcastPkt, ignoreMulticastPkt, ignoreDiscards, ignoreErrors, ignoreUnknownProtos, ignoreOutQLen)
		}

		if err != nil {
			log.Printf(ip, err)
			close(ch)
		}

		if len(wlcList) > 0 {
			chWlcStat.WlcStatsList = &wlcList
		}

		endTime = time.Now().Unix()
		chWlcStat.UseTime = (endTime - startTime)
		<-limitCh
		ch <- chWlcStat
		return
	}

	return
}
