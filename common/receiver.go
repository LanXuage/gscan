package common

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/panjf2000/ants/v2"
	"go.uber.org/zap"
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
		for i := 0; i < 10; i++ {
			r.RecvWorkers.Invoke(packets)
		}
		p, err = ants.NewPoolWithFunc(512, r.startHookFun)
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
		hookFunAndArgs.ResultCh <- result
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
	ret, _ := r.HookFunAndResultChs.LoadOrStore(name, HookFunAndResultCh{
		HookFun:  hookFun,
		ResultCh: make(chan interface{}, 10),
	})
	return ret.(HookFunAndResultCh).ResultCh
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
