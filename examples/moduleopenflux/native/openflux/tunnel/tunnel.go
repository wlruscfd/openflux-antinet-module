package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

// The client side of the OpenFlux tunnel; the wire format is raw IPv4 packets, with no framing of its own.

type TCPTunnel struct {
	gvisorStack *stack.Stack
	tunnelEP    *TunnelLinkEndpoint
	transport   transport.Transport
	startTime   time.Time
	packetCount atomic.Uint64
}

// clientAddr is fixed by the protocol: the exit node routes 10.10.10.0/24 to one client address only.
var clientAddr = tcpip.AddrFrom4([4]byte{10, 10, 10, 2})

func NewTCPTunnel(trans transport.Transport) *TCPTunnel {
	t := &TCPTunnel{
		transport: trans,
		startTime: time.Now(),
	}

	utils.Debugf("[TUNNEL] Net stack init...")
	t.gvisorStack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
	})

	if err := t.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 65536, Default: 262144, Max: 1048576}); err != nil {
		utils.Debugf("[TUNNEL] Failed to set recv buffer: %v", err)
	}
	if err := t.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPSendBufferSizeRangeOption{Min: 65536, Default: 262144, Max: 1048576}); err != nil {
		utils.Debugf("[TUNNEL] Failed to set send buffer: %v", err)
	}

	tunnelEP := NewTunnelLinkEndpoint()
	tunnelEP.onOutgoingPacket = func(data []byte) {
		trans.Send(data)
	}
	t.tunnelEP = tunnelEP

	tunnelNIC := tcpip.NICID(1)
	if err := t.gvisorStack.CreateNIC(tunnelNIC, tunnelEP); err != nil {
		utils.Debugf("[TUNNEL] CreateNIC tunnel error: %v", err)
	}

	t.setupClient(tunnelNIC)

	trans.Receive(func(data []byte) {
		tunnelEP.InjectInbound(data)
	})

	go t.printStats()
	return t
}

func (t *TCPTunnel) setupClient(tunnelNIC tcpip.NICID) {
	t.gvisorStack.AddProtocolAddress(tunnelNIC, tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   clientAddr,
			PrefixLen: 24,
		},
	}, stack.AddressProperties{})

	t.gvisorStack.AddRoute(tcpip.Route{
		Destination: header.IPv4EmptySubnet,
		NIC:         tunnelNIC,
	})
}

// DialTCP requires address to be a literal IPv4 ip:port - the caller must resolve it off-tunnel first (MODULE_API §2.3 p.2).
func (t *TCPTunnel) DialTCP(ctx context.Context, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Deliberate refusal, not a fallback to the system resolver, which would itself route through the TUN.
		return nil, fmt.Errorf("DialTCP: %q is not a literal IP (caller must resolve)", host)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("DialTCP: IPv6 not supported by this transport")
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, fmt.Errorf("port %q: %w", portStr, err)
	}

	return gonet.DialContextTCP(ctx, t.gvisorStack, tcpip.FullAddress{
		NIC:  tcpip.NICID(1),
		Addr: tcpip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]}),
		Port: uint16(port),
	}, ipv4.ProtocolNumber)
}

func (t *TCPTunnel) printStats() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := t.gvisorStack.Stats()
		utils.Debugf("[STATS] uptime=%v packets=%d connected=%d established=%d retrans=%d",
			time.Since(t.startTime).Round(time.Second),
			t.packetCount.Load(),
			stats.TCP.CurrentConnected.Value(),
			stats.TCP.CurrentEstablished.Value(),
			stats.TCP.Retransmits.Value(),
		)
	}
}
