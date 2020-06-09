package funcs

import (
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"time"

	"github.com/gaochao1/swcollector/g"
	"github.com/open-falcon/common/model"

	"github.com/52002015/sw"
	"github.com/toolkits/slice"
)

type ChDiskStat struct {
	Ip            string
	PingResult    bool
	UseTime       int64
	DiskStatsList *[]sw.DiskStats
}

type LastdiskMap struct {
	lock     *sync.RWMutex
	diskstat map[string]*[]sw.DiskStats
}

func NewLastdiskMap() {
	lastdiskmap = &LastdiskMap{
		lock:     new(sync.RWMutex),
		diskstat: make(map[string]*[]sw.DiskStats),
	}
}

func (m *LastdiskMap) Get(k string) *[]sw.DiskStats {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if val, ok := m.diskstat[k]; ok {
		return val
	}
	return nil
}

func (m *LastdiskMap) Set(k string, v *[]sw.DiskStats) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.diskstat[k] = v
	return
}

func (m *LastdiskMap) Check(k string) bool {
	m.lock.RLock()
	defer m.lock.RUnlock()
	if _, ok := m.diskstat[k]; !ok {
		return false
	}
	return true
}

var (
	DiskAliveIp []string
	lastdiskmap *LastdiskMap
)

func AllDiskIp() (allIp []string) {
	diskIp := g.Config().Switch.IpRange

	if len(diskIp) > 0 {
		for _, wip := range diskIp {
			aip := sw.ParseIp(wip)
			for _, ip := range aip {
				//This is the more delegate way
				vender, _ := sw.SysVendor(ip, community, snmpRetry, snmpTimeout)
				if vender == "AC" || vender == "AD" {
					allIp = append(allIp, ip)
				}
			}
		}
	}
	return allIp
}

func DiskMetrcis() (L []*model.MetricValue) {
	if g.Config().Switch.Enabled && len(g.Config().Switch.IpRange) > 0 {
		return diskMetrics()
		// fmt.Println("DiskMetrcis: ", diskMetrics())
	}
	return
}

func diskMetrics() (L []*model.MetricValue) {
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
		DiskAliveIp = nil
	}
	initVariable()
	allIp := AllDiskIp()
	timeout := time.Duration(g.Config().Transfer.Interval) * time.Second

	chs := make([]chan ChDiskStat, len(allIp))
	limitCh := make(chan bool, g.Config().Switch.LimitConcur)
	startTime := time.Now()
	log.Printf("UpdateDiskStats start. The number of concurrent limited to %d. IP addresses number is %d", g.Config().Switch.LimitConcur, len(allIp))
	if gosnmp {
		log.Println("get snmp message by gosnmp")
	} else {
		log.Println("get snmp message by snmpwalk")
	}
	for i, ip := range allIp {
		chs[i] = make(chan ChDiskStat)
		limitCh <- true
		go coreDiskMetrcis(ip, chs[i], limitCh)
		time.Sleep(5 * time.Millisecond)
	}
	for i, ch := range chs {
		select {
		case chDiskStat, ok := <-ch:
			if !ok {
				continue
			}

			if chDiskStat.PingResult == true && !slice.ContainsString(DiskAliveIp, chDiskStat.Ip) {
				DiskAliveIp = append(DiskAliveIp, chDiskStat.Ip)
			}
			if chDiskStat.DiskStatsList != nil {
				if g.Config().Debug {
					log.Println("IP:", chDiskStat.Ip, "PingResult:", chDiskStat.PingResult, "len_list:", len(*chDiskStat.DiskStatsList), "UsedTime:", chDiskStat.UseTime)
				}

				for _, diskStat := range *chDiskStat.DiskStatsList {
					diskNameTag := "diskName=" + diskStat.DiskName
					ip := chDiskStat.Ip
					newDiskUsedPercent := StringReg(diskStat.DiskUsedPercent)
					newDiskAvail := StringReg(diskStat.DiskAvail)
					L = append(L, GaugeValueIp(diskStat.TS, ip, "snmp.disk.DiskUsedPercent", newDiskUsedPercent, diskNameTag))
					L = append(L, GaugeValueIp(diskStat.TS, ip, "snmp.disk.DiskAvail", newDiskAvail, diskNameTag))
				}
				lastdiskmap.Set(chDiskStat.Ip, chDiskStat.DiskStatsList)
			}
		case <-time.After(timeout):
			log.Println(allIp[i] + " go runtime timeout")
		}
	}

	endTime := time.Now()
	log.Printf("UpdateDiskStats complete. Process time %s. Number of disktive ip is %d", endTime.Sub(startTime), len(DiskAliveIp))

	if g.Config().Debug {
		for i, v := range DiskAliveIp {
			log.Println("DiskAliveIp:", i, v)
		}
	}

	return
}

func coreDiskMetrcis(ip string, ch chan ChDiskStat, limitCh chan bool) {
	var startTime, endTime int64
	startTime = time.Now().Unix()

	var chDiskStat ChDiskStat

	pingResult := pingCheck(ip)

	chDiskStat.Ip = ip
	chDiskStat.PingResult = pingResult

	if !pingResult {
		endTime = time.Now().Unix()
		chDiskStat.UseTime = (endTime - startTime)
		<-limitCh
		ch <- chDiskStat
		return
	} else {
		var diskList []sw.DiskStats
		var err error
		if gosnmp {
			diskList, err = sw.ListDiskStats(ip, community, snmpTimeout, ignoreIface, snmpRetry, limitCon, ignorePkt, ignoreOperStatus, ignoreBroadcastPkt, ignoreMulticastPkt, ignoreDiscards, ignoreErrors, ignoreUnknownProtos, ignoreOutQLen)
		}

		if err != nil {
			log.Printf(ip, err)
			close(ch)
		}

		if len(diskList) > 0 {
			chDiskStat.DiskStatsList = &diskList
		}

		endTime = time.Now().Unix()
		chDiskStat.UseTime = (endTime - startTime)
		<-limitCh
		ch <- chDiskStat
		return
	}

	return
}

func StringReg(result string) interface{} {
	reg := regexp.MustCompile(`\d+`)
	if strings.Contains(result, ".") {
		reg = regexp.MustCompile(`\d+\.\d+`)
	}
	if reg == nil {
		return "0"
	}
	newResult := reg.FindAllStringSubmatch(result, -1)[0][0]

	if strings.Contains(result, ".") {
		intResult, err := strconv.ParseFloat(newResult, 2)
		if err != nil {
			log.Println("error: ", err)
			return 0
		}
		if strings.Contains(result, "K") {
			return intResult * 1000
		}
		if strings.Contains(result, "M") {
			// intResult := fmt.Sprintf("%f", intResult*1000*8)
			return intResult * 1000 * 1000
		}
		if strings.Contains(result, "G") {
			return intResult * 1000 * 1000 * 1000
		}
		return intResult
	} else {
		intResult, err := strconv.Atoi(newResult)
		if err != nil {
			return 0
		}
		if strings.Contains(result, "K") {
			return intResult * 1000
		}
		if strings.Contains(result, "M") {
			return intResult * 1000 * 1000
		}
		if strings.Contains(result, "G") {
			return intResult * 1000 * 1000 * 1000
		}
		return intResult
	}

}
