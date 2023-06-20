package service

import (
	"bytes"
	"math/rand"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/LanXuage/gscan/arp"
	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/icmp"
	"github.com/LanXuage/gscan/port"
	"github.com/google/gopacket/layers"
	cmap "github.com/orcaman/concurrent-map/v2"
	"github.com/panjf2000/ants/v2"
	"go.uber.org/zap"
)

type ServiceResult struct {
	port.TCPResult
	CPE string
}

type ServiceInfo struct {
	Conn   net.Conn
	Banner []byte
}

type ServiceTarget struct {
	IP   netip.Addr
	Port layers.TCPPort
	Rule *GScanRule
}

type ServiceScanner struct {
	TargetCh     chan *ServiceTarget
	ResultCh     chan *ServiceResult
	Timeout      time.Duration
	Workers      *ants.PoolWithFunc
	Services     cmap.ConcurrentMap[netip.Addr, cmap.ConcurrentMap[layers.TCPPort, ServiceInfo]]
	reCache      cmap.ConcurrentMap[string, regexp.Regexp]
	PortScanType uint8
	Ports        []layers.TCPPort
	gCount       int64
	sCount       int64
}

func (s *ServiceScanner) init() {
	p, err := ants.NewPoolWithFunc(10, s.sendAndMatch)
	if err != nil {
		logger.Error("Create func pool failed", zap.Error(err))
	}
	s.Workers = p
}

func (s *ServiceScanner) sendAndMatch(data interface{}) {
	target := data.(*ServiceTarget)
	isNotScaned := false
	if ipInfo, ok := s.Services.Get(target.IP); ok {
		logger.Debug("sendAndMatch1", zap.Any("isNotScaned", isNotScaned))
		isNotScaned = ipInfo.SetIfAbsent(target.Port, ServiceInfo{})
		logger.Debug("sendAndMatch1", zap.Any("isNotScaned", isNotScaned))
	} else {
		serviceInfo := cmap.NewWithCustomShardingFunction[layers.TCPPort, ServiceInfo](func(key layers.TCPPort) uint32 { return uint32(key) })
		serviceInfo.Set(target.Port, ServiceInfo{})
		logger.Debug("sendAndMatch2", zap.Any("isNotScaned", isNotScaned))
		isNotScaned = s.Services.SetIfAbsent(target.IP, serviceInfo)
		logger.Debug("sendAndMatch2", zap.Any("isNotScaned", isNotScaned))
	}
	logger.Debug("sendAndMatch", zap.Any("isNotScaned", isNotScaned))
	switch target.Rule.RuleType {
	case GSRULE_TYPE_TCP:
		s._sendAndMatch("tcp", target, isNotScaned)
	case GSRULE_TYPE_UDP:
		s._sendAndMatch("udp", target, isNotScaned)
	case GSRULE_TYPE_TCP_MUX:
		s._sendAndMatchMux("tcp", target, isNotScaned)
	case GSRULE_TYPE_UDP_MUX:
		s._sendAndMatchMux("udp", target, isNotScaned)
	}
}

func (s *ServiceScanner) _sendAndMatch(network string, target *ServiceTarget, isNotScaned bool) {

}

func (s *ServiceScanner) _sendAndMatchMux(network string, target *ServiceTarget, isNotScaned bool) {
	logger.Debug("_sendAndMatchMux", zap.Any("target", target))
	ipInfo, _ := s.Services.Get(target.IP)
	serviceInfo, _ := ipInfo.Get(target.Port)
	if isNotScaned {
		logger.Debug("connect to", zap.Any("target", target.IP.String()+":"+strconv.Itoa(int(target.Port))))
		conn, err := net.Dial(network, target.IP.String()+":"+strconv.Itoa(int(target.Port)))
		if err != nil {
			logger.Error("net.Dial", zap.Error(err))
		}
		banner := []byte{}
		buf := make([]byte, 4096)
		count, err := conn.Read(buf)
		banner = append(banner, buf[0:count]...)
		for err == nil && count == len(buf) {
			count, err = conn.Read(buf)
			banner = append(banner, buf[0:count]...)
		}
		logger.Debug("recv", zap.Any("banner", banner))
		serviceInfo.Conn = conn
		if len(banner) != 0 {
			serviceInfo.Banner = banner
		}
	}
	env := ScanEnv{
		LastResp: serviceInfo.Banner,
		Vals:     make(map[string][]byte),
	}
	serviceResult := &ServiceResult{
		TCPResult: port.TCPResult{
			ICMPScanResult: icmp.ICMPScanResult{
				ARPScanResult: arp.ARPScanResult{
					IP: target.IP,
				},
				IsActive: true,
			},
			Port: target.Port,
		},
	}
	for _, ruleItem := range (*target).Rule.Items {
		switch ruleItem.DataType {
		case GSRULE_DATA_TYPE_MATCH:
			reStr := string(common.Bytes2Runes(ruleItem.Data))
			logger.Debug("reStr", zap.Any("reStr", reStr))
			r, ok := s.reCache.Get(reStr)
			if !ok {
				rTmp, err := regexp.Compile(reStr)
				if err != nil {
					logger.Error("match", zap.Error(err), zap.Any("reStr", reStr), zap.Any("ruleItem", ruleItem))
				}
				r = *rTmp
				s.reCache.SetIfAbsent(reStr, r)
			}
			logger.Debug("match", zap.Any("data", env.LastResp))
			results := r.FindAllStringSubmatch(string(common.Bytes2Runes(env.LastResp)), -1)
			logger.Debug("match", zap.Any("results", results))
			for _, result := range results {
				for i, sname := range r.SubexpNames() {
					if i != 0 && sname != "" {
						env.Vals[sname] = common.Runes2Bytes([]rune(result[i]))
					}
				}
			}
		// https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe
		// cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
		case GSRULE_DATA_TYPE_CPE23:
			fmtStr := string(common.Bytes2Runes(ruleItem.Data))
			wfnValsTmp := strings.Split(fmtStr, ":")
			cpe := bytes.Buffer{}
			cpe.WriteString("cpe:2.3")
			i := 0
			for _, wfnVal := range wfnValsTmp {
				cpe.WriteString(":")
				logger.Debug("cpe23", zap.Any("key", wfnVal), zap.Any("Vals", env.Vals))
				if wfnVal[0] == 60 && wfnVal[len(wfnVal)-1] == 62 {
					logger.Debug("cpe23", zap.Any("key", wfnVal), zap.Any("k", wfnVal[1:len(wfnVal)-1]), zap.Any("v", string(env.Vals[wfnVal[0:len(wfnVal)-2]])))
					cpe.WriteString(string(env.Vals[wfnVal[1:len(wfnVal)-1]]))
				} else {
					cpe.WriteString(wfnVal)
				}
				i += 1
			}
			for j := 0; j < 10-i; j++ {
				cpe.WriteString(":")
			}
			logger.Debug(cpe.String())
			serviceResult.CPE = cpe.String()
		}
	}
	s.ResultCh <- serviceResult
}

func (s *ServiceScanner) waitTimeout(timeoutCh chan struct{}) {
	defer close(timeoutCh)
	for {
		time.Sleep(time.Microsecond * 200)
		if s.gCount == s.sCount && len(s.TargetCh) == 0 {
			break
		}
	}
	time.Sleep(s.Timeout)
}

func (s *ServiceScanner) goScanMany(targetIPs []netip.Addr, timeoutCh chan struct{}) {
	defer s.waitTimeout(timeoutCh)
	for _, targetIP := range targetIPs {
		for _, iface := range *common.GetActiveIfaces() {
			s.generateTarget(targetIP, iface)
		}
	}
}

func (s *ServiceScanner) generateTargetByPrefix(prefix netip.Prefix, iface common.GSIface) {
	for i := 0; i < 2; i++ {
		nIp := prefix.Addr()
		for {
			if (nIp.Is4() && nIp.AsSlice()[3] != 0 && nIp.AsSlice()[3] != 255) || (nIp.Is6() && nIp.AsSlice()[15] != 0 && (nIp.AsSlice()[14] != 255 || nIp.AsSlice()[15] != 255)) {
				if !nIp.IsValid() || !prefix.Contains(nIp) || !iface.Mask.Contains(nIp) {
					break
				} else {
					s.generateTarget(nIp, iface)
				}
			}
			if i == 1 {
				nIp = nIp.Prev()
			} else {
				nIp = nIp.Next()
			}
		}
	}
}

func (s *ServiceScanner) ScanMany(targetIPs []netip.Addr) chan struct{} {
	timeoutCh := make(chan struct{})
	go s.goScanMany(targetIPs, timeoutCh)
	return timeoutCh
}

func (s *ServiceScanner) ScanPrefix(prefix netip.Prefix) chan struct{} {
	timeoutCh := make(chan struct{})
	go s.goScanPrefix(prefix, timeoutCh)
	return timeoutCh
}

func (s *ServiceScanner) goScanPrefix(prefix netip.Prefix, timeoutCh chan struct{}) {
	defer s.waitTimeout(timeoutCh)
	for _, iface := range *arpInstance.Ifas {
		if iface.Mask.Contains(prefix.Addr()) {
			s.generateTargetByPrefix(prefix, iface)
		}
	}
}

func (s *ServiceScanner) generateTarget(ip netip.Addr, iface common.GSIface) {
	dstMac, _ := arpInstance.AHMap.Get(iface.Gateway)
	if ip == iface.IP {
		dstMac = iface.HWAddr
	}
	if len(dstMac) == 0 {
		return
	}
	dstPorts := common.GetDefaultPorts()
	if s.PortScanType == port.ALL_PORTS {
		dstPorts = &[]layers.TCPPort{}
		for i := 1; i < 65536; i++ {
			*dstPorts = append(*dstPorts, layers.TCPPort(i))
		}
	} else if s.PortScanType == port.CUSTOM_PORTS {
		dstPorts = &s.Ports
	}
	for _, port := range *dstPorts {
		logger.Debug("generateTarget", zap.Any("IP", ip), zap.Any("port", port))
		for _, rule := range *getRules() {
			s.TargetCh <- &ServiceTarget{
				IP:   ip,
				Port: port,
				Rule: &rule,
			}
			s.gCount += 1
		}
	}
}

func (s *ServiceScanner) ScanLocalNet() chan struct{} {
	timeoutCh := make(chan struct{})
	go s.generateLocalNetTarget(timeoutCh)
	return timeoutCh
}

func (s *ServiceScanner) generateLocalNetTarget(timeoutCh chan struct{}) {
	defer s.waitTimeout(timeoutCh)
	for _, iface := range *common.GetActiveIfaces() {
		s.generateTargetByPrefix(iface.Mask, iface)
	}
}

func (s *ServiceScanner) scan() {
	for target := range s.TargetCh {
		s.Workers.Invoke(target)
		s.sCount += 1
	}
}

func newServiceScanner() *ServiceScanner {
	rand.Seed(time.Now().Unix())
	s := &ServiceScanner{
		TargetCh:     make(chan *ServiceTarget, 10),
		ResultCh:     make(chan *ServiceResult, 10),
		Timeout:      3 * time.Second,
		Services:     cmap.NewWithCustomShardingFunction[netip.Addr, cmap.ConcurrentMap[layers.TCPPort, ServiceInfo]](common.Fnv32),
		reCache:      cmap.New[regexp.Regexp](),
		PortScanType: port.DEFAULT_PORTS,
		Ports:        []layers.TCPPort{},
	}
	s.init()
	go s.scan()
	return s
}
