package receiver_test

import (
	"testing"
	"time"

	"github.com/LanXuage/gscan/receiver"

	"github.com/google/gopacket"
)

type TestPacketReceiver struct {
	Observer receiver.PacketReceiverObserver
	ResultCh chan gopacket.Packet
}

func (tpr *TestPacketReceiver) Receive(packet gopacket.Packet) {
	tpr.ResultCh <- packet
	tpr.Observer.RemovePacketReceiver(tpr)
}

func TestReceiver(t *testing.T) {
	pro := receiver.GetPacketReceiverObserver()
	resultCh := make(chan gopacket.Packet, 256)
	pro.AddPacketReceiver(&TestPacketReceiver{
		Observer: pro,
		ResultCh: resultCh,
	})
	timeoutCh := make(chan struct{})
	go func(timeoutCh chan struct{}) {
		defer close(timeoutCh)
		time.Sleep(time.Second * 10)
	}(timeoutCh)
	select {
	case <-timeoutCh:
		t.Error("timeout")
	case packet := <-resultCh:
		t.Log(packet)
	}
}
