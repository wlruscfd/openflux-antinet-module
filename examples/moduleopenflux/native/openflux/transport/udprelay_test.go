package transport

import (
	"testing"
	"time"
)

func TestUDPRelayRoundTrip(t *testing.T) {
	a := NewUDPRelayTransport("127.0.0.1:41100", "127.0.0.1:41101", "shared-secret", true, DefaultConfig())
	b := NewUDPRelayTransport("127.0.0.1:41101", "127.0.0.1:41100", "shared-secret", false, DefaultConfig())

	received := make(chan []byte, 1)
	b.Receive(func(data []byte) { received <- data })

	if err := a.Start(); err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	defer a.Stop()
	if err := b.Start(); err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	defer b.Stop()

	if err := a.Send([]byte("hello relay")); err != nil {
		t.Fatalf("a.Send: %v", err)
	}

	select {
	case got := <-received:
		if string(got) != "hello relay" {
			t.Fatalf("got %q, want %q", got, "hello relay")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the relayed packet")
	}
}

func TestUDPRelayWrongSecretDropsSilently(t *testing.T) {
	a := NewUDPRelayTransport("127.0.0.1:41102", "127.0.0.1:41103", "secret-a", true, DefaultConfig())
	b := NewUDPRelayTransport("127.0.0.1:41103", "127.0.0.1:41102", "secret-b", false, DefaultConfig())

	received := make(chan []byte, 1)
	b.Receive(func(data []byte) { received <- data })

	if err := a.Start(); err != nil {
		t.Fatalf("a.Start: %v", err)
	}
	defer a.Stop()
	if err := b.Start(); err != nil {
		t.Fatalf("b.Start: %v", err)
	}
	defer b.Stop()

	if err := a.Send([]byte("should not decrypt")); err != nil {
		t.Fatalf("a.Send: %v", err)
	}

	select {
	case got := <-received:
		t.Fatalf("expected the mismatched-secret packet to be dropped, got %q", got)
	case <-time.After(300 * time.Millisecond):
	}
}
