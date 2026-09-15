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

// PacketCounts reports how many packets have flowed each direction through
// this endpoint since it was created - a cheap way to tell "nothing is
// reaching the gateway at all" apart from "packets arrive but relaying
// fails downstream" when traffic isn't flowing.
func (e *TunnelLinkEndpoint) PacketCounts() (in, out uint64) {
	return e.packetIn.Load(), e.packetOut.Load()
}

// SetOutgoingPacketHandler registers the callback invoked with each raw IP
// packet gvisor wants to emit on this NIC. Exported so packages outside
// tunnel (e.g. gateway, which wires this endpoint to a TUN file descriptor
// instead of a Transport) can reuse this endpoint without a second
// implementation of the stack.LinkEndpoint interface.
func (e *TunnelLinkEndpoint) SetOutgoingPacketHandler(fn func([]byte)) {
	e.onOutgoingPacket = fn
}

func (e *TunnelLinkEndpoint) InjectInbound(data []byte) {
	e.packetIn.Add(1)
	if utils.IsVerbose() {
		// ParsePacketInfo parses IP/TCP headers and builds a string on every
		// call - worth skipping when nothing will read it, since this runs
		// once per inbound packet.
		utils.Debugf("<- %d bytes - %s\n", len(data), network.ParsePacketInfo(data))
	}

	// A packet already in flight (e.g. a FIN triggered by the caller
	// tearing the connection down) can race a concurrent Close()/Destroy()
	// detaching this endpoint - dispatcher is a plain interface value, so
	// reading it unsynchronized with Attach's write is a real data race,
	// not just a theoretical one: it's what let a nil dispatcher slip
	// through here and crash.
	e.dispatcherMu.RLock()
	dispatcher := e.dispatcher
	e.dispatcherMu.RUnlock()
	if dispatcher == nil {
		return
	}

	// This tunnel is TCP-only by construction (see the SOCKS5 UDP ASSOCIATE
	// 0x07 rejection elsewhere) - the stack's own protocol registration
	// matches (ipv4 + tcp/udp, no icmp; see tunnel.go), and its NAT/
	// forwarding code (SetForwardingDefaultAndAllNICs, exit-node only)
	// nil-pointer-panics trying to handle a protocol it has no registered
	// handler for instead of returning an error. Confirmed in production
	// logs: proto=1 (ICMP) - a client's own OS routing a ping, or its own
	// path-MTU probing, into the tunnel's default route, not anything this
	// tool ever sends itself. Dropping it here, before it can reach
	// DeliverNetworkPacket, is the same outcome the recover() below already
	// produces (packet dropped, everything else keeps working) without
	// paying for a panic - and, on an exit node under real traffic, without
	// the same bad packet being retransmitted by the sender and re-panicking
	// on every single retry.
	if len(data) < 20 || data[9] != 6 {
		return
	}

	// gvisor panics on some inputs it doesn't expect instead of returning an
	// error - seen in production as "panic: unexpected transport protocol =
	// 0" from its NAT/conntrack code (SetForwardingDefaultAndAllNICs, used
	// by the exit node) on a packet it apparently didn't like. This call
	// runs on a shared per-transport goroutine (the covert channel's own
	// read loop), so an unrecovered panic here doesn't just drop this one
	// packet - it takes the whole process down, disconnecting every client
	// this exit node was serving. One bad packet dropped beats that. Kept
	// as a backstop even after the protocol check above: that check only
	// covers the one specific cause already confirmed in production, not
	// every input gvisor might ever choke on.
	defer func() {
		if r := recover(); r != nil {
			// Always logged (not gated behind utils.IsVerbose() like the
			// line above) - this is already the rare, exceptional case
			// worth paying attention to, and the whole point is capturing
			// what kind of packet triggers it without needing --debug
			// already running when it happens again.
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

func (e *TunnelLinkEndpoint) MTU() uint32                                 { return 1500 }
func (e *TunnelLinkEndpoint) MaxHeaderLength() uint16                      { return 0 }
func (e *TunnelLinkEndpoint) LinkAddress() tcpip.LinkAddress               { return "\x02\x00\x00\x00\x00\x01" }
func (e *TunnelLinkEndpoint) Capabilities() stack.LinkEndpointCapabilities { return stack.CapabilityNone }
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
func (e *TunnelLinkEndpoint) Wait()                                        {}
func (e *TunnelLinkEndpoint) ARPHardwareType() header.ARPHardwareType      { return header.ARPHardwareNone }
func (e *TunnelLinkEndpoint) AddHeader(*stack.PacketBuffer)                {}
func (e *TunnelLinkEndpoint) Close()                                       {}
func (e *TunnelLinkEndpoint) SetMTU(uint32)                                {}
func (e *TunnelLinkEndpoint) SetLinkAddress(tcpip.LinkAddress)             {}
func (e *TunnelLinkEndpoint) ParseHeader(*stack.PacketBuffer) bool         { return true }
func (e *TunnelLinkEndpoint) SetOnCloseAction(func())                      {}
