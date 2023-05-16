package service

import (
	"math/rand"
	"net"
	"net/netip"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/panjf2000/ants/v2"
	"go.uber.org/zap"
)

type ServiceResult struct {
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
}

func (s *ServiceScanner) init() {
	p, err := ants.NewPoolWithFunc(10, s.SendAndMatch)
	if err != nil {
		logger.Error("Create func pool failed", zap.Error(err))
	}
	s.Workers = p
}

func (s *ServiceScanner) SendAndMatch(data interface{}) {
	target := data.(ServiceTarget)
	switch target.Rule.RuleType {
	case GSRULE_TYPE_NORMAL_TCP:
		s.SendAndMatchNormal("tcp", &target)
	case GSRULE_TYPE_NORMAL_UDP:
		s.SendAndMatchNormal("tcp", &target)
	}
}

func (s *ServiceScanner) SendAndMatchNormal(network string, target *ServiceTarget) {
	conn, err := net.Dial(network, target.IP.String()+":"+target.Port.String())
	if err != nil {
		logger.Error("net.Dial", zap.Error(err))
	}
	conn.Read()
}

func (s *ServiceScanner) Scan() {
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
	go s.Scan()
	return s
}
