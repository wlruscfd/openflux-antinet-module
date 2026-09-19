package transport

import (
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
)

// protectFD is set once per process by mobile.StartTunnel when the caller
// supplies a Protector - see ProtectedDialer's doc comment for why this
// exists. Left nil for the CLI/exit-node binary, where there is no VPN
// interface for a socket to be captured by, so Control below is then a
// no-op.
var protectFD func(fd int) bool

// SetProtector registers fn as the callback ProtectedDialer routes every
// socket it opens through before it connects. Pass nil to disable protection
// again (e.g. once the tunnel stops).
//
// AntiNet divergence from openflux-server: DNS no longer comes through here.
// Name resolution is done by the shared/dns canon shim, which takes its
// protect hook as an explicit parameter instead of this package-level
// callback - the module contract (MODULE_API section 4) requires that form,
// because a global left unset fails at runtime rather than at build time.
func SetProtector(fn func(fd int) bool) {
	protectFD = fn
}

// ProtectedDialer returns a *net.Dialer that calls the registered protector
// (if any) on every socket it opens, before it connects.
//
// On Android, once a VpnService's tunnel is up, ALL of the device's
// outbound traffic - including the VPN app's own sockets - is routed into
// that tunnel by default. A transport's own connections (to Yandex Docs,
// its DNS lookups, ...) are exactly the traffic that's supposed to be
// carried *through* the tunnel, so without exempting them the transport
// ends up dialing itself: the connection attempt gets captured by the
// tunnel it's trying to establish, which has nowhere to forward it, and
// the whole thing deadlocks - the client can reach neither the doc nor
// DNS. VpnService.protect(fd) is Android's way to mark a socket as exempt;
// Protector (mobile.go) is how that reaches Go from Kotlin.
func ProtectedDialer() *net.Dialer {
	return &net.Dialer{
		Timeout: 30 * time.Second,
		Control: protectControl,
	}
}

// defaultBootstrapDNSServers are queried directly (never through the
// tunnel, via ProtectedDialer) to resolve the transport's own hostnames -
// see the shared/dns canon (dns_netresolver.go) for why Go can't be left to
// pick a nameserver itself here. Order matters: the first one reachable wins.
// Both are well-known public resolvers chosen for being reachable from
// networks where this tool is actually used, not tied to any one profile's
// configured (tunneled) DNSUpstream.
var defaultBootstrapDNSServers = []string{"77.88.8.8:53", "8.8.8.8:53"}

// bootstrapDNSServers is what the resolver actually queries - starts out as
// defaultBootstrapDNSServers, but SetBootstrapDNSServers can replace it for
// a session (see that function's doc comment). The reader is the shared/dns
// canon shim, which the helper hands BootstrapDNSServers as its provider.
//
// AntiNet divergence from openflux-server: guarded by bootstrapMu. The host
// pushes a fresh resolver list into a RUNNING helper on every network
// change (module event "dns="), so this slice is written while transport
// lookups are in flight. A racing read of a slice header is not merely a
// stale value - it is a mismatched pointer/length pair, i.e. a read past
// the end of the new backing array. Every access below therefore goes
// through bootstrapMu, and callers read via BootstrapDNSServers(), which
// hands back a copy rather than the live slice.
var (
	bootstrapMu         sync.RWMutex
	bootstrapDNSServers = append([]string(nil), defaultBootstrapDNSServers...)
)

// BootstrapDNSServers returns a copy of the resolver list currently in
// effect. Exported so the gateway can reuse the exact same
// reachable-directly resolvers when it serves DNS for sites that bypass the
// tunnel (see gateway.dns.go) - whatever SetBootstrapDNSServers last set
// applies there too, for the same reason: if the caller had to force a
// specific resolver to get anywhere on this network, a site bypassing the
// tunnel needs that same override just as much as the transport's own
// bootstrap lookups do.
func BootstrapDNSServers() []string {
	bootstrapMu.RLock()
	defer bootstrapMu.RUnlock()
	return append([]string(nil), bootstrapDNSServers...)
}

// SetBootstrapDNSServers forcibly replaces the resolver(s) queried to
// resolve the transport's own hostnames (docs.yandex.ru and
// friends) before the tunnel exists to carry anything else - normally two
// fixed public resolvers (see defaultBootstrapDNSServers), which is fine
// until the network a device is actually on can't reach them at all (a
// carrier that blackholes third-party resolvers, a captive network that
// only routes to its own DNS) while a different, locally-reachable server
// works fine. A non-empty list here REPLACES the defaults outright rather
// than being tried alongside them - the caller already knows the defaults
// don't work for them, and falling back to a server already established as
// unreachable would just re-add the delay this exists to avoid. An empty
// list restores the defaults.
//
// AntiNet divergence from openflux-server: safe to call at any time,
// including while lookups are in flight (see bootstrapDNSServers). Upstream
// documents this as "call it before starting a tunnel", which holds for a
// CLI that configures itself once; a helper driven by host network events
// has no such moment - the whole point is to replace the list precisely
// because the network changed under a running tunnel. Note the normalize
// loop stays OUTSIDE the lock: it only touches its own local slice.
func SetBootstrapDNSServers(servers []string) {
	if len(servers) == 0 {
		bootstrapMu.Lock()
		bootstrapDNSServers = append([]string(nil), defaultBootstrapDNSServers...)
		bootstrapMu.Unlock()
		return
	}
	normalized := make([]string, len(servers))
	for i, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		normalized[i] = s
	}
	bootstrapMu.Lock()
	bootstrapDNSServers = normalized
	bootstrapMu.Unlock()
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
