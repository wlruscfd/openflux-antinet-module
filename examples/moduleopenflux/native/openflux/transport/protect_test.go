package transport

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestProtectedDialerCallsProtectorWithFD(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	var gotFD int
	SetProtector(func(fd int) bool {
		gotFD = fd
		return true
	})
	t.Cleanup(func() { SetProtector(nil) })

	conn, err := ProtectedDialer().Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if gotFD <= 0 {
		t.Errorf("protector fd = %d, want a real positive fd", gotFD)
	}
}

func TestProtectedDialerFailsWhenProtectorRejects(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	SetProtector(func(fd int) bool { return false })
	t.Cleanup(func() { SetProtector(nil) })

	_, err = ProtectedDialer().Dial("tcp", ln.Addr().String())
	if err == nil {
		t.Fatalf("expected an error when the protector rejects the socket")
	}
	if !strings.Contains(err.Error(), "protect") {
		t.Errorf("error = %q, want it to mention protection failing", err)
	}
}

// TestProtectedResolverIgnoresRequestedAddress guards the actual Android bug: Go's resolver asks Dial to connect to 127.0.0.1:53, where nothing listens.
func TestProtectedResolverIgnoresRequestedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	original := bootstrapDNSServers
	bootstrapDNSServers = []string{ln.Addr().String()}
	t.Cleanup(func() { bootstrapDNSServers = original })

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		conn.Close()
	}()

	conn, err := ProtectedResolver().Dial(context.Background(), "tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatalf("bootstrap server was never dialed - Dial used the (broken) requested address instead")
	}
}

func TestSetBootstrapDNSServersReplacesNotAppends(t *testing.T) {
	t.Cleanup(func() { SetBootstrapDNSServers(nil) })

	SetBootstrapDNSServers([]string{"192.0.2.1:53"})
	got := BootstrapDNSServers()
	if len(got) != 1 || got[0] != "192.0.2.1:53" {
		t.Fatalf("BootstrapDNSServers() = %v, want exactly [192.0.2.1:53]", got)
	}
}

func TestSetBootstrapDNSServersAppendsDefaultPort(t *testing.T) {
	t.Cleanup(func() { SetBootstrapDNSServers(nil) })

	SetBootstrapDNSServers([]string{"192.0.2.1"})
	got := BootstrapDNSServers()
	if len(got) != 1 || got[0] != "192.0.2.1:53" {
		t.Fatalf("BootstrapDNSServers() = %v, want exactly [192.0.2.1:53]", got)
	}
}

func TestSetBootstrapDNSServersEmptyRestoresDefaults(t *testing.T) {
	SetBootstrapDNSServers([]string{"192.0.2.1:53"})
	SetBootstrapDNSServers(nil)

	got := BootstrapDNSServers()
	if len(got) != len(defaultBootstrapDNSServers) {
		t.Fatalf("BootstrapDNSServers() = %v, want the defaults %v", got, defaultBootstrapDNSServers)
	}
	for i, want := range defaultBootstrapDNSServers {
		if got[i] != want {
			t.Errorf("BootstrapDNSServers()[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func TestProtectedDialerNoProtectorIsANoop(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	SetProtector(nil)

	conn, err := ProtectedDialer().Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial with no protector registered: %v", err)
	}
	conn.Close()
}
