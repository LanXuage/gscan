package common

import (
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/panjf2000/ants/v2"
	"go.uber.org/zap"
)

type Receiver struct {
	State          uint8
	Lock           sync.Mutex
	HookFuns       sync.Map
	ResultChs      sync.Map
	RecvWorkers    *ants.PoolWithFunc
	HookFunWorkers *ants.PoolWithFunc
}

type HookFunAndArgs struct {
	Packet  gopacket.Packet
	Name    string
	HookFun func(packet gopacket.Packet) interface{}
}

func newReceiver() *Receiver {
	r := &Receiver{
		State:     0,
		HookFuns:  sync.Map{},
		ResultChs: sync.Map{},
	}
	r.init()
	return r
}

func (r *Receiver) init() {
	for _, gsInterface := range *GetActiveInterfaces() {
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
	hookFunAndArgs := hookFunAndArgsI.(HookFunAndArgs)
	result := hookFunAndArgs.HookFun(hookFunAndArgs.Packet)
	if result != nil {
		if ret, ok := r.ResultChs.Load(hookFunAndArgs.Name); ok {
			ret.(chan interface{}) <- result
		}
	}
}

func (r *Receiver) recv(packets interface{}) {
	for packet := range packets.(chan gopacket.Packet) {
		r.HookFuns.Range(func(key, value any) bool {
			r.HookFunWorkers.Invoke(HookFunAndArgs{
				Packet:  packet,
				Name:    key.(string),
				HookFun: value.(func(packet gopacket.Packet) interface{}),
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
		r.ResultChs.Store(name, make(chan interface{}, 10))
		r.HookFuns.Store(name, hookFun)
	}
	ret, _ := r.ResultChs.Load(name)
	return ret.(chan interface{})
}

func (r *Receiver) Unregister(name string) {
	if ret, ok := r.ResultChs.Load(name); ok {
		r.Lock.Lock()
		defer r.Lock.Unlock()
		r.ResultChs.Delete(name)
		r.HookFuns.Delete(name)
		close(ret.(chan interface{}))
	}
}

var instance = newReceiver()

func GetReceiver() *Receiver {
	return instance
}
