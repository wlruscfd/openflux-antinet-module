package tunnel

import (
	"log"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"

	"universal-bypass-tool/network"
	"universal-bypass-tool/utils"
)

type TunnelLinkEndpoint struct {
	dispatcherMu     sync.RWMutex
	dispatcher       stack.NetworkDispatcher
	onOutgoingPacket func([]byte)
	packetIn         atomic.Uint64
	packetOut        atomic.Uint64
}

func NewTunnelLinkEndpoint() *TunnelLinkEndpoint {
	return &TunnelLinkEndpoint{}
}

// PacketCounts is a cheap way to tell "nothing is reaching the gateway" apart from "packets arrive but relaying fails".
func (e *TunnelLinkEndpoint) PacketCounts() (in, out uint64) {
	return e.packetIn.Load(), e.packetOut.Load()
}

// SetOutgoingPacketHandler is exported so packages outside tunnel (e.g. gateway) can reuse this endpoint.
func (e *TunnelLinkEndpoint) SetOutgoingPacketHandler(fn func([]byte)) {
	e.onOutgoingPacket = fn
}

func (e *TunnelLinkEndpoint) InjectInbound(data []byte) {
	e.packetIn.Add(1)
	if utils.IsVerbose() {
		// ParsePacketInfo builds a string on every call, so it's skipped when nothing will read it.
		utils.Debugf("<- %d bytes - %s\n", len(data), network.ParsePacketInfo(data))
	}

	// dispatcher is a plain interface value; reading it unsynchronized with Attach's write let a nil dispatcher crash here.
	e.dispatcherMu.RLock()
	dispatcher := e.dispatcher
	e.dispatcherMu.RUnlock()
	if dispatcher == nil {
		return
	}

	// The stack only registers TCP/UDP handlers; anything else (e.g. ICMP) nil-pointer-panics in gvisor's NAT code instead of erroring.
	if len(data) < 20 || (data[9] != 6 && data[9] != 17) {
		return
	}

	// Backstop: gvisor can still panic on other inputs (seen in production as "unexpected transport protocol = 0"), taking the whole process down otherwise.
	defer func() {
		if r := recover(); r != nil {
			// Always logged (not gated behind IsVerbose) since this is already the rare, exceptional case worth capturing.
			log.Printf("[TUNNEL] recovered from a panic dispatching an inbound packet (%d bytes, %s): %v",
				len(data), network.ParsePacketInfo(data), r)
		}
	}()

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte{}, data...)),
	})
	dispatcher.DeliverNetworkPacket(ipv4.ProtocolNumber, pkt)
}

func (e *TunnelLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		data := pkt.ToView().ToSlice()
		e.packetOut.Add(1)
		if e.onOutgoingPacket != nil {
			e.onOutgoingPacket(data)
		}
		n++
	}
	return n, nil
}

func (e *TunnelLinkEndpoint) MTU() uint32                    { return 1500 }
func (e *TunnelLinkEndpoint) MaxHeaderLength() uint16        { return 0 }
func (e *TunnelLinkEndpoint) LinkAddress() tcpip.LinkAddress { return "\x02\x00\x00\x00\x00\x01" }
func (e *TunnelLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityNone
}
func (e *TunnelLinkEndpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcherMu.Lock()
	e.dispatcher = dispatcher
	e.dispatcherMu.Unlock()
}
func (e *TunnelLinkEndpoint) IsAttached() bool {
	e.dispatcherMu.RLock()
	defer e.dispatcherMu.RUnlock()
	return e.dispatcher != nil
}
func (e *TunnelLinkEndpoint) Wait()                                   {}
func (e *TunnelLinkEndpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (e *TunnelLinkEndpoint) AddHeader(*stack.PacketBuffer)           {}
func (e *TunnelLinkEndpoint) Close()                                  {}
func (e *TunnelLinkEndpoint) SetMTU(uint32)                           {}
func (e *TunnelLinkEndpoint) SetLinkAddress(tcpip.LinkAddress)        {}
func (e *TunnelLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (e *TunnelLinkEndpoint) SetOnCloseAction(func())                 {}
