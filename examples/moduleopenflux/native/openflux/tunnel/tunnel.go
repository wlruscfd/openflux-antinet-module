package tunnel

import (
	"context"
	"fmt"
	"net"
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

// Клиентская сторона туннеля OpenFlux.
//
// Wire-формат — СЫРЫЕ IPv4-пакеты в транспорте: у клиента свой gVisor-стек с адресом 10.10.10.2/24,
// его link-endpoint (endpoint.go) отдаёт исходящие пакеты в `trans.Send`, а всё принятое инжектит
// обратно через `InjectInbound`; exit-node на той стороне высыпает их в raw-socket. Собственного
// фрейминга у протокола нет, и заводить его нельзя: любой «свой» заголовок exit-node скормит в
// `InjectInbound`, gVisor разберёт его как IPv4 и молча дропнет — туннель поднимется, трафик не
// пойдёт.

type TCPTunnel struct {
	gvisorStack *stack.Stack
	tunnelEP    *TunnelLinkEndpoint
	transport   transport.Transport
	startTime   time.Time
}

// clientAddr — адрес клиента в туннельной подсети. Фиксирован протоколом: exit-node маршрутизирует
// 10.10.10.0/24 в туннельный NIC, а адрес клиента в нём один. Отсюда же следует, что ДВА клиента на
// одном exit-node сталкиваются — поэтому дескриптор объявляет `parallelPing: false`.
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

	// Max bounds throughput at Max*8/RTT; the old 1MB capped this tunnel's ~200-400ms RTT connections to ~25-30 Mbit/s from window exhaustion alone. Only a ceiling — `Default` still decides what a connection actually allocates.
	if err := t.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPReceiveBufferSizeRangeOption{Min: 65536, Default: 262144, Max: 8 * 1024 * 1024}); err != nil {
		utils.Debugf("[TUNNEL] Failed to set recv buffer: %v", err)
	}
	if err := t.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber,
		&tcpip.TCPSendBufferSizeRangeOption{Min: 65536, Default: 262144, Max: 8 * 1024 * 1024}); err != nil {
		utils.Debugf("[TUNNEL] Failed to set send buffer: %v", err)
	}
	// gvisor's default MinRTO (200ms) is shorter than a typical round trip through this covert channel, so without raising the floor gvisor's TCP mistakes ordinary latency for loss and retransmits data still in flight.
	minRTO := tcpip.TCPMinRTOOption(1500 * time.Millisecond)
	if err := t.gvisorStack.SetTransportProtocolOption(tcp.ProtocolNumber, &minRTO); err != nil {
		utils.Debugf("[TUNNEL] Failed to set min RTO: %v", err)
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

// DialTCP — дозвон ВНУТРИ туннеля. `address` обязан быть литеральным `ip:port` (IPv4): резолв —
// обязанность вызывающего, его protected off-tunnel резолвером (MODULE_API §2.3 п.2), иначе
// резолв-сокет уходит в TUN. Дедлайн берётся из ctx — стек gVisor сам по себе не сдаётся никогда.
func (t *TCPTunnel) DialTCP(ctx context.Context, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("split %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Осознанный отказ, а не фоллбэк на системный резолв: тот уходит в TUN (Husi-pattern —
		// UID модуля ВНУТРИ туннеля), и «прямая» проба начинает отвечать про туннель.
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
		// ⛔ Счёт берётся У ЭНДПОИНТА, который пакеты и переносит ([TunnelLinkEndpoint.PacketCounts]
		// — `packetIn` растёт в `InjectInbound`, `packetOut` в исходящем обработчике). Прежде здесь
		// стояло собственное поле `TCPTunnel.packetCount`, у которого был этот единственный
		// читатель и НИ ОДНОГО писателя: строка печатала `packets=0` всегда — и на живом туннеле,
		// и на мёртвом. Врала она ровно в том разборе, ради которого заведена («доходит ли хоть
		// что-то до шлюза»), поэтому поле снято, а не «дописан инкремент» где-то ещё: считать
		// обязано то место, через которое пакет физически проходит.
		in, out := t.tunnelEP.PacketCounts()
		utils.Debugf("[STATS] uptime=%v packets=%d/%d connected=%d established=%d retrans=%d",
			time.Since(t.startTime).Round(time.Second),
			in, out,
			stats.TCP.CurrentConnected.Value(),
			stats.TCP.CurrentEstablished.Value(),
			stats.TCP.Retransmits.Value(),
		)
	}
}
