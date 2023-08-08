package common

import (
	"net/netip"
	"time"
)

const (
	MAX_CHANNEL_SIZE = 256
)

type IScanner interface {
	Init(s *Scanner)
	GenerateTarget(ip netip.Addr, iface GSIface, s *Scanner)
	GenerateTargetByPrefix(prefix netip.Prefix, iface GSIface, s *Scanner)
	Close()
}

type Scanner struct {
	Timeout  time.Duration // 抓包超时时间
	TargetCh chan interface{}
	ResultCh chan interface{}
	GCount   int64
	SCount   int64
	Scanner  IScanner
}

func NewScanner(iScanner IScanner) *Scanner {
	s := &Scanner{
		Timeout:  6 * time.Second,
		TargetCh: make(chan interface{}, MAX_CHANNEL_SIZE),
		ResultCh: make(chan interface{}, MAX_CHANNEL_SIZE),
		GCount:   0,
		SCount:   0,
		Scanner:  iScanner,
	}
	s.Scanner.Init(s)
	return s
}

func (s *Scanner) Close() {
	defer s.Scanner.Close()
	defer close(s.TargetCh)
	defer close(s.ResultCh)
}

func (s *Scanner) WaitTimeout(timeoutCh chan struct{}) {
	defer close(timeoutCh)
	for {
		time.Sleep(time.Microsecond * 200)
		if s.GCount == s.SCount && len(s.TargetCh) == 0 {
			break
		}
	}
	time.Sleep(s.Timeout)
}

func (s *Scanner) goScanMany(targetIPs []netip.Addr, timeoutCh chan struct{}) {
	defer s.WaitTimeout(timeoutCh)
	for _, targetIP := range targetIPs {
		for _, iface := range *GetActiveIfaces() {
			s.Scanner.GenerateTarget(targetIP, iface, s)
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
		s.Scanner.GenerateTargetByPrefix(prefix, iface, s)
	}
}

func (s *Scanner) ScanPrefix(prefix netip.Prefix) chan struct{} {
	timeoutCh := make(chan struct{})
	go s.goScanPrefix(prefix, timeoutCh)
	return timeoutCh
}

func (s *Scanner) ScanLocalNet() chan struct{} {
	timeoutCh := make(chan struct{})
	go s.goScanLocalNet(timeoutCh)
	return timeoutCh
}

func (s *Scanner) goScanLocalNet(timeoutCh chan struct{}) {
	defer s.WaitTimeout(timeoutCh)
	for _, iface := range *GetActiveIfaces() {
		s.Scanner.GenerateTargetByPrefix(iface.Mask, iface, s)
	}
}
