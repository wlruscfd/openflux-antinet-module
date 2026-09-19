package yandex

import (
	"testing"
	"time"

	"universal-bypass-tool/transport"
)

// TestPeerSilenceDetector pins the AntiNet divergence that covers the incident of
// 2026-09-17 15:08-15:16: the WebSocket to Yandex stayed healthy (its read deadline
// is fed by Yandex's own Socket.IO pings) while the exit-node sharing the document
// had stopped answering, so the tunnel carried nothing for eight minutes and three
// host nudges in a row could not fix it.
//
// Deployment can only show that the detector leaves a HEALTHY session alone - making
// a third-party exit-node go silent on demand is not something a test can arrange.
// So the state machine itself is pinned here: silence is declared only after
// peerSilenceFactor missed keep-alives, and any word from the peer clears it.
func TestPeerSilenceDetector(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.KeepAliveInterval = 20 * time.Millisecond
	window := cfg.KeepAliveInterval * peerSilenceFactor

	tr := NewYandexDocsTransport("https://docs.yandex.ru/docs/view?url=test", cfg)

	// Nothing heard yet - the session is still coming up, so there is no basis to
	// judge it. Declaring silence here would kill every connection at birth.
	if tr.peerSilent() {
		t.Fatal("a session that has heard nothing yet must not count as silent")
	}

	tr.notePeerAlive()
	if tr.peerSilent() {
		t.Fatal("a peer heard from just now must not count as silent")
	}

	// Still inside the window: a single missed keep-alive is jitter, not silence.
	time.Sleep(window / 2)
	if tr.peerSilent() {
		t.Fatalf("peer must not be declared silent inside the %v window", window)
	}

	// Past the window with nothing from the peer - this is the 15:10 state, and it
	// is what the old code could not see at all.
	time.Sleep(window)
	if !tr.peerSilent() {
		t.Fatalf("peer silent for more than %v must be detected", window)
	}

	// One word from the peer clears it: the session is usable again and must not be
	// torn down.
	tr.notePeerAlive()
	if tr.peerSilent() {
		t.Fatal("a message from the peer must clear the silence")
	}
}

// TestPeerSilenceDisabledWithoutKeepAlive guards the escape hatch: with keep-alive
// switched off there is no interval to count missed beats against, so the detector
// must stay quiet rather than tear sessions down on an invented schedule.
func TestPeerSilenceDisabledWithoutKeepAlive(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.KeepAliveInterval = 0

	tr := NewYandexDocsTransport("https://docs.yandex.ru/docs/view?url=test", cfg)
	tr.notePeerAlive()
	time.Sleep(10 * time.Millisecond)

	if tr.peerSilent() {
		t.Fatal("with keep-alive disabled the detector must never fire")
	}
}
