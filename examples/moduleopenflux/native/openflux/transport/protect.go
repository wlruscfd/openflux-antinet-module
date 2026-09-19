package transport

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

// protectFD is set once per process by mobile.StartTunnel; left nil for the CLI/exit-node binary, where Control is then a no-op.
var protectFD func(fd int) bool

// SetProtector registers fn as the callback ProtectedDialer/ProtectedResolver route every socket through before it connects.
func SetProtector(fn func(fd int) bool) {
	protectFD = fn
}

// ProtectedDialer exempts the transport's own sockets from the VPN tunnel, since otherwise it would deadlock dialing itself.
func ProtectedDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 30 * time.Second,
		Control: protectControl,
	}
}

// defaultBootstrapDNSServers are queried directly, never through the tunnel; order matters, first reachable wins.
var defaultBootstrapDNSServers = []string{"77.88.8.8:53", "8.8.8.8:53"}

// bootstrapDNSServers is what ProtectedResolver actually queries; SetBootstrapDNSServers can replace it for a session.
var bootstrapDNSServers = append([]string(nil), defaultBootstrapDNSServers...)

// BootstrapDNSServers returns a copy of the resolver list currently in effect, so the gateway can reuse it too.
func BootstrapDNSServers() []string {
	return append([]string(nil), bootstrapDNSServers...)
}

// SetBootstrapDNSServers replaces the defaults outright (not concurrency-safe); call before starting a tunnel, not while running.
func SetBootstrapDNSServers(servers []string) {
	if len(servers) == 0 {
		bootstrapDNSServers = append([]string(nil), defaultBootstrapDNSServers...)
		return
	}
	normalized := make([]string, len(servers))
	for i, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		normalized[i] = s
	}
	bootstrapDNSServers = normalized
}

// ProtectedResolver forces the pure-Go resolver and ignores the dialed address, which is unusable on Android (see Dial below).
func ProtectedResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		// Android's dnsReadConfig has no /etc/resolv.conf to read and falls back to an unreachable 127.0.0.1:53.
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var lastErr error
			for _, server := range bootstrapDNSServers {
				conn, err := ProtectedDialer().DialContext(ctx, network, server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

func protectControl(network, address string, c syscall.RawConn) error {
	if protectFD == nil {
		return nil
	}
	var protectErr error
	if err := c.Control(func(fd uintptr) {
		if !protectFD(int(fd)) {
			protectErr = fmt.Errorf("failed to protect socket for %s %s", network, address)
		}
	}); err != nil {
		return err
	}
	return protectErr
}
