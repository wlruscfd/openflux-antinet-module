package yandex

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"universal-bypass-tool/transport"
)

// --- Send ---------------------------------------------------------------

// TestSendQueuesEvenWhileDisconnected guards a real bug ported from
// openflux-server: Send used to reject with "transport not connected" for
// the entire window between a drop and the next successful reconnect, even
// though the session's WriteQueue survives a reconnect specifically so
// queued data doesn't have to be lost (see connectToDoc's existingSession
// handling and Send's own doc comment). A disconnected transport with no
// session at all must still fail - only "has a session, but IsConnected()
// is momentarily false" should succeed.
func TestSendQueuesEvenWhileDisconnected(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig(), nil)
	tr.session = &DocSession{WriteQueue: make(chan []byte, 4)}
	// Deliberately not calling tr.SetConnected(true) - this is the state
	// during a reconnect: a (possibly stale) session exists, but the
	// transport doesn't consider itself connected right now.

	if err := tr.Send([]byte("hello")); err != nil {
		t.Fatalf("Send while disconnected but with a session = %v, want nil", err)
	}

	select {
	case got := <-tr.session.WriteQueue:
		if string(got) != "hello" {
			t.Errorf("queued %q, want %q", got, "hello")
		}
	default:
		t.Fatalf("Send returned nil but nothing was queued")
	}
}

func TestSendFailsWithNoSessionAtAll(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig(), nil)
	if err := tr.Send([]byte("hello")); err == nil {
		t.Fatalf("expected an error before any session has ever been established")
	}
}

// --- self-echo filtering -------------------------------------------------

// TestHandleMessageDropsOwnEcho guards the actual production bug this
// filter exists for (found and fixed in openflux-server, this module's
// sibling project): Yandex's doc broadcasts every "cursor" event to every
// participant, sender included, so a packet this transport itself just
// sent (via writerLoop, which calls markSent) comes straight back over the
// same socket. Before wasRecentlySent existed, handleMessage handed that to
// CallReceive indistinguishably from real peer data - the client's own
// outgoing traffic reinjected into its own tunnel endpoint.
func TestHandleMessageDropsOwnEcho(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig(), nil)

	sent := []byte("own outgoing packet bytes")
	tr.markSent(sent)

	var received [][]byte
	tr.Receive(func(data []byte) { received = append(received, data) })

	echoMsg := `42["message",{"type":"cursor","cursor":"18;` + b64(sent) + `"}]`
	tr.handleMessage(nil, []byte(echoMsg))

	if len(received) != 0 {
		t.Fatalf("handleMessage delivered our own echoed packet to CallReceive: %v", received)
	}
}

// TestHandleMessageDeliversRealPeerData is TestHandleMessageDropsOwnEcho's
// counterpart: data this transport never sent must still reach CallReceive
// - the echo filter must not swallow everything indiscriminately.
func TestHandleMessageDeliversRealPeerData(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig(), nil)

	var received [][]byte
	tr.Receive(func(data []byte) { received = append(received, data) })

	peerData := []byte("genuine data from the other side")
	msg := `42["message",{"type":"cursor","cursor":"18;` + b64(peerData) + `"}]`
	tr.handleMessage(nil, []byte(msg))

	if len(received) != 1 || string(received[0]) != string(peerData) {
		t.Fatalf("CallReceive got %v, want [%q]", received, peerData)
	}
}

func b64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// --- backoffDelay -----------------------------------------------------

// TestBackoffDelayGrowsAndCaps guards against a real regression this
// module's DefaultConfig used to have (ReconnectDelay: 0, which makes
// exponential backoff a permanent no-op - 0 * anything is still 0): each
// attempt should produce a longer delay than the last, up to
// MaxReconnectDelay, never past it.
func TestBackoffDelayGrowsAndCaps(t *testing.T) {
	tr := NewYandexDocsTransport("http://example.invalid", transport.TransportConfig{
		ReconnectDelay:      100 * time.Millisecond,
		ReconnectMultiplier: 2,
		MaxReconnectDelay:   1 * time.Second,
	}, nil)

	got0 := tr.backoffDelay(0)
	got1 := tr.backoffDelay(1)
	got2 := tr.backoffDelay(2)
	gotCapped := tr.backoffDelay(10)

	if got0 != 100*time.Millisecond {
		t.Errorf("backoffDelay(0) = %v, want 100ms", got0)
	}
	if got1 <= got0 {
		t.Errorf("backoffDelay(1) = %v, want > backoffDelay(0) = %v", got1, got0)
	}
	if got2 <= got1 {
		t.Errorf("backoffDelay(2) = %v, want > backoffDelay(1) = %v", got2, got1)
	}
	if gotCapped != 1*time.Second {
		t.Errorf("backoffDelay(10) = %v, want capped at MaxReconnectDelay = 1s", gotCapped)
	}
}

func TestBackoffDelayZeroConfigIsNoop(t *testing.T) {
	tr := NewYandexDocsTransport("http://example.invalid", transport.TransportConfig{
		ReconnectDelay: 0,
	}, nil)
	if got := tr.backoffDelay(5); got != 0 {
		t.Errorf("backoffDelay with ReconnectDelay=0 = %v, want 0 (explicitly disabled)", got)
	}
}

// --- fetchDocInfo safe parsing --------------------------------------------

// TestFetchDocInfoMalformedConfig guards against a real crash class: every
// field extracted from Yandex's client-config JSON used to be an unchecked
// type assertion, which panics on a goroutine with no recover() - crashing
// the whole helper - the moment Yandex serves a page shaped even slightly
// differently than expected (error/maintenance page, A/B-tested layout,
// partly-loaded response, a view-only fallback because someone else has the
// doc open). Every documented shape below must return a plain error
// instead.
func TestFetchDocInfoMalformedConfig(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"no client-config script at all", `<html><body>error page</body></html>`},
		{"invalid json", `<script id="client-config">{not json`},
		{"missing officeActionData", `<script id="client-config">{"foo":1}</script>`},
		{"officeActionData wrong type", `<script id="client-config">{"officeActionData":"nope"}</script>`},
		{"nil editor_config", `<script id="client-config">{"officeActionData":{"editor_config":null}}</script>`},
		{
			"missing balancer_url",
			`<script id="client-config">{"officeActionData":{"editor_config":{"document":{"key":"k"},"token":"t"}}}</script>`,
		},
		{
			"document wrong type",
			`<script id="client-config">{"officeActionData":{"balancer_url":"https://x","editor_config":{"document":"nope","token":"t"}}}</script>`,
		},
		{
			"missing token",
			`<script id="client-config">{"officeActionData":{"balancer_url":"https://x","editor_config":{"document":{"key":"k"}}}}</script>`,
		},
		{
			"missing document key",
			`<script id="client-config">{"officeActionData":{"balancer_url":"https://x","editor_config":{"document":{},"token":"t"}}}</script>`,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(c.body))
			}))
			defer srv.Close()

			tr := NewYandexDocsTransport(srv.URL, transport.DefaultConfig(), nil)
			if _, err := tr.fetchDocInfo(srv.URL, "user1"); err == nil {
				t.Fatalf("fetchDocInfo did not error on malformed body %q", c.body)
			}
		})
	}
}

func TestFetchDocInfoValidConfig(t *testing.T) {
	body := `<script id="client-config">{"officeActionData":{"balancer_url":"https://balancer.example",` +
		`"editor_config":{"token":"tok123","document":{"key":"doc-key-1","fileType":"docx","url":"https://x/doc","title":"T"}}}}</script>`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()

	tr := NewYandexDocsTransport(srv.URL, transport.DefaultConfig(), nil)
	info, err := tr.fetchDocInfo(srv.URL, "user1")
	if err != nil {
		t.Fatalf("fetchDocInfo() error = %v, want nil", err)
	}
	if info.DocID != "doc-key-1" || info.Token != "tok123" || info.Host != "balancer.example" {
		t.Errorf("fetchDocInfo() = %+v, missing expected fields", info)
	}
	if !strings.Contains(info.WsURL, "doc-key-1") {
		t.Errorf("WsURL = %q, want it to contain the doc key", info.WsURL)
	}
}
