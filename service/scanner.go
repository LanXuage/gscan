package service

import (
	"bytes"
	"math/rand"
	"net"
	"net/netip"
	"regexp"
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
	TargetCh chan *ServiceTarget
	ResultCh chan *ServiceResult
	Timeout  time.Duration
	Workers  *ants.PoolWithFunc
	Services cmap.ConcurrentMap[netip.Addr, cmap.ConcurrentMap[layers.TCPPort, ServiceInfo]]
	reCache  cmap.ConcurrentMap[string, regexp.Regexp]
}

func (s *ServiceScanner) init() {
	p, err := ants.NewPoolWithFunc(10, s.sendAndMatch)
	if err != nil {
		logger.Error("Create func pool failed", zap.Error(err))
	}
	s.Workers = p
}

func (s *ServiceScanner) sendAndMatch(data interface{}) {
	target := data.(ServiceTarget)
	isNotScaned := false
	if ipInfo, ok := s.Services.Get(target.IP); ok {
		isNotScaned = ipInfo.SetIfAbsent(target.Port, ServiceInfo{})
	} else {
		serviceInfo := cmap.NewWithCustomShardingFunction[layers.TCPPort, ServiceInfo](func(key layers.TCPPort) uint32 { return uint32(key) })
		serviceInfo.Set(target.Port, ServiceInfo{})
		isNotScaned = !s.Services.SetIfAbsent(target.IP, serviceInfo)
	}
	switch target.Rule.RuleType {
	case GSRULE_TYPE_TCP:
		s._sendAndMatch("tcp", &target, isNotScaned)
	case GSRULE_TYPE_UDP:
		s._sendAndMatch("udp", &target, isNotScaned)
	case GSRULE_TYPE_TCP_MUX:
		s._sendAndMatchMux("tcp", &target, isNotScaned)
	case GSRULE_TYPE_UDP_MUX:
		s._sendAndMatchMux("udp", &target, isNotScaned)
	}
}

func (s *ServiceScanner) _sendAndMatch(network string, target *ServiceTarget, isNotScaned bool) {

}

func (s *ServiceScanner) _sendAndMatchMux(network string, target *ServiceTarget, isNotScaned bool) {
	ipInfo, _ := s.Services.Get(target.IP)
	serviceInfo, _ := ipInfo.Get(target.Port)
	if isNotScaned {
		conn, err := net.Dial(network, target.IP.String()+":"+target.Port.String())
		if err != nil {
			logger.Error("net.Dial", zap.Error(err))
		}
		banner := []byte{}
		buf := make([]byte, 4096)
		count, err := conn.Read(buf)
		for err != nil {
			banner = append(banner, buf[0:count]...)
			count, err = conn.Read(buf)
		}
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
			r, ok := s.reCache.Get(reStr)
			if !ok {
				rTmp, err := regexp.Compile(reStr)
				if err != nil {
					logger.Error("match", zap.Error(err), zap.Any("reStr", reStr), zap.Any("ruleItem", ruleItem))
				}
				r = *rTmp
				s.reCache.SetIfAbsent(reStr, r)
			}
			results := r.FindAllStringSubmatch(string(common.Bytes2Runes(env.LastResp)), -1)
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
				if wfnVal[0] == 60 && wfnVal[len(wfnVal)-1] == 62 {
					cpe.WriteString(string(env.Vals[wfnVal[0:len(wfnVal)-2]]))
				} else {
					cpe.WriteString(wfnVal)
				}
				i += 1
			}
			for j := 0; j < 10-i; j++ {
				cpe.WriteString(":")
			}
			serviceResult.CPE = cpe.String()
		}
	}
}

func (s *ServiceScanner) scan() {
	for target := range s.TargetCh {
		s.Workers.Invoke(target)
	}
}

func newServiceScanner() *ServiceScanner {
	rand.Seed(time.Now().Unix())
	s := &ServiceScanner{
		TargetCh: make(chan *ServiceTarget, 10),
		ResultCh: make(chan *ServiceResult, 10),
		Timeout:  3 * time.Second,
	}
	s.init()
	go s.scan()
	return s
}
