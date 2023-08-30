package scanner

import (
	"net/netip"

	"github.com/LanXuage/gscan/common"
)

const (
	MAX_CHANNEL_SIZE = 256
)

type Scanner interface {
	Scan(targets []netip.Addr) ScanTask
	ScanPrefix(prefix netip.Prefix) ScanTask
	ScanLocalNet() ScanTask
}

type ScannerCore interface {
	Send(target interface{})
	GenerateTarget(iface common.GSIface, ip netip.Addr, task ScanTask)
	GenerateTargetByPrefix(iface common.GSIface, prefix netip.Prefix, task ScanTask)
}

type ScannerImpl struct {
	TargetCh chan interface{}
	core     ScannerCore
}

func NewScanner(core ScannerCore) *ScannerImpl {
	s := &ScannerImpl{
		TargetCh: make(chan interface{}, MAX_CHANNEL_SIZE),
		core:     core,
	}
	go s.goRun()
	return s
}

func (s *ScannerImpl) goRun() {
	for target := range s.TargetCh {
		s.core.Send(target)
	}
}

func (s *ScannerImpl) goScan(targets []netip.Addr, task ScanTask) {
	for _, iface := range *common.GetActiveIfaces() {
		for _, ip := range targets {
			s.core.GenerateTarget(iface, ip, task)
		}
	}
	task.Done()
}

func (s *ScannerImpl) Scan(targets []netip.Addr) ScanTask {
	task := &ScanTaskImpl{
		state:    0,
		TargetCh: s.TargetCh,
		ResultCh: make(chan interface{}, MAX_CHANNEL_SIZE),
	}
	go s.goScan(targets, task)
	return task
}

func (s *ScannerImpl) goScanPrefix(prefix netip.Prefix, task ScanTask) {
	for _, iface := range *common.GetActiveIfaces() {
		if iface.Mask.Contains(prefix.Addr()) {
			s.core.GenerateTargetByPrefix(iface, prefix, task)
			return
		}
	}
	for _, iface := range *common.GetActiveIfaces() {
		s.core.GenerateTargetByPrefix(iface, prefix, task)
	}
	task.Done()
}

func (s *ScannerImpl) goScanLocalNet(task ScanTask) {
	for _, iface := range *common.GetActiveIfaces() {
		s.core.GenerateTargetByPrefix(iface, iface.Mask, task)
	}
	task.Done()
}

func (s *ScannerImpl) ScanPrefix(prefix netip.Prefix) ScanTask {
	task := &ScanTaskImpl{
		state:    0,
		TargetCh: s.TargetCh,
		ResultCh: make(chan interface{}, MAX_CHANNEL_SIZE),
	}
	go s.goScanPrefix(prefix, task)
	return task
}

func (s *ScannerImpl) ScanLocalNet() ScanTask {
	task := &ScanTaskImpl{
		state:    0,
		TargetCh: s.TargetCh,
		ResultCh: make(chan interface{}, MAX_CHANNEL_SIZE),
	}
	go s.goScanLocalNet(task)
	return task
}
