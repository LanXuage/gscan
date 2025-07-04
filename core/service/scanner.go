package service

import (
	"bytes"
	"crypto/tls"
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
	CPE      string
	Protocol string
}

type ServiceInfo struct {
	Conn       net.Conn
	Banner     []byte
	RespMap    cmap.ConcurrentMap[string, []byte]
	IsTLS      bool
	HasMatched bool
}

type ServiceTarget struct {
	IP   netip.Addr
	Port layers.TCPPort
	Rule common.GScanRule
}

type ServiceScanner struct {
	common.IScanner
	Workers      *ants.PoolWithFunc
	Services     cmap.ConcurrentMap[netip.Addr, cmap.ConcurrentMap[layers.TCPPort, ServiceInfo]]
	reCache      cmap.ConcurrentMap[string, regexp.Regexp]
	PortScanType uint8
	Ports        []layers.TCPPort
}

func (s *ServiceScanner) Close() {}

func (s *ServiceScanner) Init() {
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
		isNotScaned = ipInfo.SetIfAbsent(target.Port, ServiceInfo{
			RespMap: cmap.New[[]byte](),
		})
		logger.Debug("sendAndMatch1", zap.Any("isNotScaned", isNotScaned))
		if !isNotScaned {
			serviceInfo, _ := ipInfo.Get(target.Port)
			if serviceInfo.HasMatched {
				return
			}
		}
	} else {
		ipInfo := cmap.NewWithCustomShardingFunction[layers.TCPPort, ServiceInfo](func(key layers.TCPPort) uint32 { return uint32(key) })
		ipInfo.Set(target.Port, ServiceInfo{
			RespMap: cmap.New[[]byte](),
		})
		logger.Debug("sendAndMatch2", zap.Any("isNotScaned", isNotScaned))
		isNotScaned = s.Services.SetIfAbsent(target.IP, ipInfo)
		logger.Debug("sendAndMatch2", zap.Any("isNotScaned", isNotScaned))
	}
	logger.Debug("sendAndMatch", zap.Any("isNotScaned", isNotScaned))
	s._sendAndMatch(target, isNotScaned)
}

func (s *ServiceScanner) _sendAndMatch(target *ServiceTarget, isNotScaned bool) {
	logger.Debug("_sendAndMatchMux", zap.Any("target", target), zap.Any("isNotScaned", isNotScaned))
	ipInfo, _ := s.Services.Get(target.IP)
	serviceInfo, _ := ipInfo.Get(target.Port)
	network := "tcp"
	if target.Rule.RuleType == common.GSRULE_TYPE_UDP || target.Rule.RuleType == common.GSRULE_TYPE_UDP_MUX {
		network = "udp"
	}
	if isNotScaned || target.Rule.RuleType == common.GSRULE_TYPE_UDP || target.Rule.RuleType == common.GSRULE_TYPE_TCP {
		targetAddr := target.IP.String() + ":" + strconv.Itoa(int(target.Port))
		logger.Debug("connect to", zap.Any("target", targetAddr))
		// try TLS
		var conn net.Conn
		var err error
		if serviceInfo.Conn != nil {
			serviceInfo.Conn.Close()
			if serviceInfo.IsTLS {
				conn, err = tls.Dial(network, targetAddr, &tls.Config{InsecureSkipVerify: true})
			} else {
				conn, err = net.Dial(network, targetAddr)
			}
		} else {
			conn, err = tls.Dial(network, targetAddr, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				conn, err = net.Dial(network, targetAddr)
			} else {
				serviceInfo.IsTLS = true
			}
		}
		if err != nil {
			logger.Debug("net.Dial", zap.Error(err))
			return
		}
		banner := []byte{}
		logger.Debug("recv", zap.Any("len", len(target.Rule.Items)), zap.Any("dataType", target.Rule.Items[0].DataType))
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(s.Timeout / 2))
		count, err := conn.Read(buf)
		banner = append(banner, buf[0:count]...)
		for err == nil && count == len(buf) {
			count, err = conn.Read(buf)
			banner = append(banner, buf[0:count]...)
		}
		logger.Debug("recv", zap.Any("banner", banner))
		serviceInfo.Conn = conn
		serviceInfo.Banner = banner
		ipInfo.Set(target.Port, serviceInfo)
	}
	for serviceInfo.Banner == nil {
		serviceInfo, _ = ipInfo.Get(target.Port)
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
		case common.GSRULE_DATA_TYPE_MATCH:
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
			if results == nil {
				return
			}
			for _, result := range results {
				for i, sname := range r.SubexpNames() {
					if i != 0 && sname != "" {
						env.Vals[sname] = common.Runes2Bytes([]rune(result[i]))
					}
				}
			}
		case common.GSRULE_DATA_TYPE_SEND:
			serviceInfo.Conn.SetWriteDeadline(time.Now().Add(s.Timeout / 2))
			serviceInfo.Conn.Write(ruleItem.Data)
			data := []byte{}
			buf := make([]byte, 4096)
			serviceInfo.Conn.SetReadDeadline(time.Now().Add(s.Timeout / 2))
			count, err := serviceInfo.Conn.Read(buf)
			data = append(data, buf[0:count]...)
			for err == nil && count == len(buf) {
				count, err = serviceInfo.Conn.Read(buf)
				data = append(data, buf[0:count]...)
			}
			env.LastResp = data
		case common.GSRULE_DATA_TYPE_SEND_MUX:
			key := string(common.Bytes2Runes(ruleItem.Data))
			data, ok := serviceInfo.RespMap.Get(key)
			if !ok {
				serviceInfo.Conn.SetWriteDeadline(time.Now().Add(s.Timeout / 2))
				n, err := serviceInfo.Conn.Write(ruleItem.Data)
				logger.Debug("send", zap.Any("err", err), zap.Any("n", n))
				data = []byte{}
				buf := make([]byte, 4096)
				serviceInfo.Conn.SetReadDeadline(time.Now().Add(s.Timeout / 2))
				count, err := serviceInfo.Conn.Read(buf)
				logger.Debug("read", zap.Any("buf", buf[0:count]))
				data = append(data, buf[0:count]...)
				for err == nil && count == len(buf) {
					count, err = serviceInfo.Conn.Read(buf)
					data = append(data, buf[0:count]...)
				}
				serviceInfo.RespMap.SetIfAbsent(key, data)
			}
			env.LastResp = data
			logger.Debug("GSRULE_DATA_TYPE_SEND_MUX", zap.Any("key", key), zap.Any("lastResp", env.LastResp))
		case common.GSRULE_DATA_TYPE_PROTOCOL:
			if serviceInfo.IsTLS {
				serviceResult.Protocol = "tls(" + string(ruleItem.Data) + ")"
			} else {
				serviceResult.Protocol = string(ruleItem.Data)
			}
		case common.GSRULE_DATA_TYPE_CPE23:
			// https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe
			// cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
			fmtStr := string(common.Bytes2Runes(ruleItem.Data))
			wfnValsTmp := strings.Split(fmtStr, ":")
			cpe := bytes.Buffer{}
			cpe.WriteString("cpe:2.3")
			i := 0
			for _, wfnVal := range wfnValsTmp {
				if len(wfnVal) == 0 {
					continue
				}
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
				cpe.WriteString(":*")
			}
			logger.Debug(cpe.String())
			serviceResult.CPE = cpe.String()
		}
	}
	logger.Debug("s", zap.Any("env", env))
	logger.Debug("s", zap.Any("s", serviceResult))
	s.ResultCh <- serviceResult
}

func (s *ServiceScanner) GenerateTarget(ip netip.Addr, iface common.GSIface, targetCh chan interface{}, resultCh chan interface{}) {
	dstMac, _ := arpInstance.Scanner.(*arp.ARPScanner).AHMap.Get(iface.Gateway)
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
				Rule: rule,
			}
			s.GCount += 1
		}
	}
}

func (s *ServiceScanner) ScanLocalNet() chan struct{} {
	timeoutCh := make(chan struct{})
	go s.generateLocalNetTarget(timeoutCh)
	return timeoutCh
}

func (s *ServiceScanner) generateTargetByPrefix(prefix netip.Prefix, iface common.GSIface, targetCh chan interface{}, resultCh chan interface{}) {
	for i := 0; i < 2; i++ {
		nIp := prefix.Addr()
		for {
			if (nIp.Is4() && nIp.AsSlice()[3] != 0 && nIp.AsSlice()[3] != 255) || (nIp.Is6() && nIp.AsSlice()[15] != 0 && (nIp.AsSlice()[14] != 255 || nIp.AsSlice()[15] != 255)) {
				if !nIp.IsValid() || !prefix.Contains(nIp) {
					break
				} else {
					s.GenerateTarget(nIp, iface, targetCh, resultCh)
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

func (s *ServiceScanner) generateLocalNetTarget(timeoutCh chan struct{}) {
	defer s.WaitTimeout(timeoutCh)
	for _, iface := range *common.GetActiveIfaces() {
		s.GenerateTargetByPrefix(iface.Mask, iface)
	}
}

func (s *ServiceScanner) scan() {
	for target := range s.TargetCh {
		s.Workers.Invoke(target)
		s.SCount += 1
	}
}

func newServiceScanner() *ServiceScanner {
	rand.Seed(time.Now().Unix())
	s := &ServiceScanner{
		Scanner:      *common.NewScanner(),
		Services:     cmap.NewWithCustomShardingFunction[netip.Addr, cmap.ConcurrentMap[layers.TCPPort, ServiceInfo]](common.Fnv32),
		reCache:      cmap.New[regexp.Regexp](),
		PortScanType: port.DEFAULT_PORTS,
		Ports:        []layers.TCPPort{},
	}
	s.Init()
	go s.scan()
	return s
}
