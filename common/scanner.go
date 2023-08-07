package common

import (
	"net/netip"
	"time"
)

type IScanner interface {
	GenerateTarget(ip netip.Addr, iface GSIface)
}

type Scanner struct {
	IScanner
	Timeout  time.Duration // 抓包超时时间
	TargetCh chan interface{}
	ResultCh chan interface{}
	gCount   int64
	sCount   int64
}

func (s *Scanner) Close() {
	defer close(s.TargetCh)
	defer close(s.ResultCh)
}

func (s *Scanner) WaitTimeout(timeoutCh chan struct{}) {
	defer close(timeoutCh)
	for {
		time.Sleep(time.Microsecond * 200)
		if s.gCount == s.sCount && len(s.TargetCh) == 0 {
			break
		}
	}
	time.Sleep(s.Timeout)
}

func (s *Scanner) goScanMany(targetIPs []netip.Addr, timeoutCh chan struct{}) {
	defer s.WaitTimeout(timeoutCh)
	for _, targetIP := range targetIPs {
		for _, iface := range *GetActiveIfaces() {
			s.GenerateTarget(targetIP, iface)
		}
	}
}

func (s *Scanner) ScanMany(targetIPs []netip.Addr) chan struct{} {
	timeoutCh := make(chan struct{})
	go s.goScanMany(targetIPs, timeoutCh)
	return timeoutCh
}

func (s *Scanner) goScanPrefix(prefix netip.Prefix, timeoutCh chan struct{}) {
	defer s.WaitTimeout(timeoutCh)
	for _, iface := range *GetActiveIfaces() {
		s.GenerateTargetByPrefix(prefix, iface)
	}
}

func (s *Scanner) ScanPrefix(prefix netip.Prefix) chan struct{} {
	timeoutCh := make(chan struct{})
	go s.goScanPrefix(prefix, timeoutCh)
	return timeoutCh
}

func (s *Scanner) GenerateTargetByPrefix(prefix netip.Prefix, iface GSIface) {
	for i := 0; i < 2; i++ {
		nIp := prefix.Addr()
		for {
			if (nIp.Is4() && nIp.AsSlice()[3] != 0 && nIp.AsSlice()[3] != 255) || (nIp.Is6() && nIp.AsSlice()[15] != 0 && (nIp.AsSlice()[14] != 255 || nIp.AsSlice()[15] != 255)) {
				if !nIp.IsValid() || !prefix.Contains(nIp) {
					break
				} else {
					s.GenerateTarget(nIp, iface)
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

func (s *Scanner) GenerateTarget(ip netip.Addr, iface GSIface) {
	logger.Panic("GenerateTarget need to be implemented. ")
}
