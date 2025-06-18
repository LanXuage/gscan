package receiver

import (
	"github.com/LanXuage/gscan/common"
	mapset "github.com/deckarep/golang-set"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/panjf2000/ants/v2"
	"go.uber.org/zap"
)

const (
	MAX_NOTIFY_FUNC_POOL_SIZE = 512
)

type PacketReceiver interface {
	Receive(packet gopacket.Packet)
}

type PacketReceiverObserver interface {
	AddPacketReceiver(packetReceiver PacketReceiver)
	RemovePacketReceiver(packetReceiver PacketReceiver)
}

type PacketReceiverAndPacket struct {
	Receiver PacketReceiver
	Packet   gopacket.Packet
}

type PacketReceiverObserverImpl struct {
	PacketReceivers       mapset.Set
	PacketReceiverWorkers *ants.PoolWithFunc
	NotifyWorkers         *ants.PoolWithFunc
}

func (p *PacketReceiverObserverImpl) AddPacketReceiver(packetReceiver PacketReceiver) {
	p.PacketReceivers.Add(packetReceiver)
}

func (p *PacketReceiverObserverImpl) RemovePacketReceiver(packetReceiver PacketReceiver) {
	p.PacketReceivers.Remove(packetReceiver)
}

func (p *PacketReceiverObserverImpl) receivePacket(iPackets interface{}) {
	for packet := range iPackets.(chan gopacket.Packet) {
		p.PacketReceivers.Each(func(item interface{}) bool {
			p.NotifyWorkers.Invoke(&PacketReceiverAndPacket{
				Receiver: item.(PacketReceiver),
				Packet:   packet,
			})
			return true
		})
	}
}

func (p *PacketReceiverObserverImpl) notifyPacketReceivers(iPacketReceiverAndArgs interface{}) {
	packetReceiverAndPacket := iPacketReceiverAndArgs.(*PacketReceiverAndPacket)
	packetReceiverAndPacket.Receiver.Receive(packetReceiverAndPacket.Packet)
}

func NewPacketReceiverObserverImpl() *PacketReceiverObserverImpl {
	packetReceiverObserverImpl := &PacketReceiverObserverImpl{
		PacketReceivers: mapset.NewSet(),
	}
	for _, gsInterface := range *common.GetActiveIfaces() {
		src := gopacket.NewPacketSource(gsInterface.Handle, layers.LayerTypeEthernet)
		workers, err := ants.NewPoolWithFunc(len(*common.GetActiveIfaces()), packetReceiverObserverImpl.receivePacket)
		if err != nil {
			logger.Error("Create func pool failed", zap.Error(err))
		}
		packetReceiverObserverImpl.PacketReceiverWorkers = workers
		packets := src.Packets()
		packetReceiverObserverImpl.PacketReceiverWorkers.Invoke(packets)
		workers, err = ants.NewPoolWithFunc(MAX_NOTIFY_FUNC_POOL_SIZE, packetReceiverObserverImpl.notifyPacketReceivers)
		if err != nil {
			logger.Error("Create hookFunc pool failed", zap.Error(err))
		}
		packetReceiverObserverImpl.NotifyWorkers = workers
	}
	return packetReceiverObserverImpl
}

var logger *zap.Logger

var instance PacketReceiverObserver

func GetPacketReceiverObserver() PacketReceiverObserver {
	return instance
}

func init() {
	logger = common.GetLogger()
	instance = NewPacketReceiverObserverImpl()
}
