package scanner

import (
	"time"
)

type ScanTask interface {
	PutTarget(target interface{})
	PutResult(result interface{})
	GetResults(timeout time.Duration) chan interface{}
	Done()
}

type ScanTaskImpl struct {
	state    uint8
	count    uint64
	ResultCh chan interface{}
	TargetCh chan interface{}
	timeout  time.Duration
}

func (s *ScanTaskImpl) PutTarget(target interface{}) {
	s.TargetCh <- target
	s.count += 1
}

func (s *ScanTaskImpl) PutResult(result interface{}) {
	s.ResultCh <- result
	s.count -= 1
}

func (s *ScanTaskImpl) Done() {
	s.state = 1
}

func (s *ScanTaskImpl) goMonitor() {
	for {
		time.Sleep(500 * time.Millisecond)
		if s.state == 1 && len(s.TargetCh) == 0 {
			if s.count > 0 {
				time.Sleep(s.timeout)
			}
			close(s.ResultCh)
			return
		}
	}
}

func (s *ScanTaskImpl) GetResults(timeout time.Duration) chan interface{} {
	s.timeout = timeout
	go s.goMonitor()
	return s.ResultCh
}
