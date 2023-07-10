package common

import (
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/panjf2000/ants/v2"
	"go.uber.org/zap"
)

const (
	MAX_RESULT_CHANNEL_SIZE = 256
	MAX_HOOK_FUNC_POOL_SIZE = 512
	WORKERS                 = 2
)

type Receiver struct {
	HookFunAndResultChs sync.Map
	RecvWorkers         *ants.PoolWithFunc
	HookFunWorkers      *ants.PoolWithFunc
}

type HookFunAndResultCh struct {
	HookFun  func(packet gopacket.Packet) interface{}
	ResultCh chan interface{}
}

type HookFunResultChAndArgs struct {
	HookFunAndResultCh
	Packet gopacket.Packet
}

func newReceiver() *Receiver {
	r := &Receiver{
		HookFunAndResultChs: sync.Map{},
	}
	r.init()
	return r
}

func (r *Receiver) init() {
	for _, gsInterface := range *GetActiveIfaces() {
		src := gopacket.NewPacketSource(gsInterface.Handle, layers.LayerTypeEthernet)
		logger.Debug("Start receiver", zap.String("gsIface", gsInterface.Name))
		p, err := ants.NewPoolWithFunc(10, r.recv)
		if err != nil {
			logger.Error("Create func pool failed", zap.Error(err))
		}
		r.RecvWorkers = p
		packets := src.Packets()
		for i := 0; i < WORKERS; i++ {
			r.RecvWorkers.Invoke(packets)
		}
		p, err = ants.NewPoolWithFunc(MAX_HOOK_FUNC_POOL_SIZE, r.startHookFun)
		if err != nil {
			logger.Error("Create hookFunc pool failed", zap.Error(err))
		}
		r.HookFunWorkers = p
	}
}

func (r *Receiver) startHookFun(hookFunAndArgsI interface{}) {
	hookFunAndArgs := hookFunAndArgsI.(HookFunResultChAndArgs)
	result := hookFunAndArgs.HookFun(hookFunAndArgs.Packet)
	if result != nil {
		if ret, ok := r.ResultChs.Load(hookFunAndArgs.Name); ok {
			resultCh := ret.(chan interface{})
			for len(resultCh) == MAX_RESULT_CHANNEL_SIZE {
				time.Sleep(3 * time.Second)
			}
			resultCh <- result
		}
	}
}

func (r *Receiver) recv(packets interface{}) {
	for packet := range packets.(chan gopacket.Packet) {
		r.HookFunAndResultChs.Range(func(key, value any) bool {
			r.HookFunWorkers.Invoke(HookFunResultChAndArgs{
				HookFunAndResultCh: value.(HookFunAndResultCh),
				Packet:             packet,
			})
			return true
		})
	}
}

func (r *Receiver) Register(name string, hookFun func(gopacket.Packet) interface{}) chan interface{} {
	r.ResultChs.Load(name)
	if _, ok := r.ResultChs.Load(name); !ok {
		r.Lock.Lock()
		defer r.Lock.Unlock()
		r.ResultChs.Store(name, make(chan interface{}, MAX_RESULT_CHANNEL_SIZE))
		r.HookFuns.Store(name, hookFun)
	}
	ret, _ := r.ResultChs.Load(name)
	return ret.(chan interface{})
}

func (r *Receiver) Unregister(name string) {
	if ret, ok := r.HookFunAndResultChs.LoadAndDelete(name); ok {
		close(ret.(HookFunAndResultCh).ResultCh)
	}
}

var instance = newReceiver()

func GetReceiver() *Receiver {
	return instance
}
