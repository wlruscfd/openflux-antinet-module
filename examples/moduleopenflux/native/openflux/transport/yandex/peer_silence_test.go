package yandex

import (
	"testing"
	"time"

	"universal-bypass-tool/transport"
)

func TestPeerSilent(t *testing.T) {
	t.Run("no frame heard yet is not silence", func(t *testing.T) {
		tr := &YandexDocsTransport{}
		if tr.peerSilent() {
			t.Fatal("session that has not heard a single frame must not count as silent")
		}
	})

	t.Run("keep-alive disabled has no verdict", func(t *testing.T) {
		tr := &YandexDocsTransport{}
		cfg := transport.DefaultConfig()
		cfg.KeepAliveInterval = 0
		tr.BaseTransport = transport.NewBaseTransport(cfg)
		tr.notePeerMsg()
		time.Sleep(10 * time.Millisecond)
		if tr.peerSilent() {
			t.Fatal("with keep-alive disabled there is no basis to judge, verdict must be not-silent")
		}
	})

	t.Run("fresh frame, then silence past the window", func(t *testing.T) {
		tr := &YandexDocsTransport{}
		cfg := transport.DefaultConfig()
		cfg.KeepAliveInterval = 20 * time.Millisecond
		tr.BaseTransport = transport.NewBaseTransport(cfg)

		tr.notePeerMsg()
		if tr.peerSilent() {
			t.Fatal("frame just arrived: peer is alive")
		}

		// The exact window boundary is deliberately not asserted: time.Sleep always
		// overshoots, so a check sitting precisely on the edge would be flaky for no
		// reason. Assert well inside the window, then well past it.
		time.Sleep(cfg.KeepAliveInterval * peerSilenceFactor / 2)
		if tr.peerSilent() {
			t.Fatal("half a window of silence still counts as alive")
		}

		time.Sleep(cfg.KeepAliveInterval * peerSilenceFactor)
		if !tr.peerSilent() {
			t.Fatal("past the silence window the peer must count as gone")
		}

		// Any frame from the peer revives the session again.
		tr.notePeerMsg()
		if tr.peerSilent() {
			t.Fatal("a frame from the peer must clear the silence")
		}
	})
}
