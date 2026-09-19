package yandex

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
)

// --- Send ---------------------------------------------------------------

// TestSendQueuesEvenWhileDisconnected guards a real bug: Send used to reject during a reconnect even though WriteQueue survives it.
func TestSendQueuesEvenWhileDisconnected(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())
	tr.session = &DocSession{WriteQueue: make(chan []byte, 4)}
	// Deliberately not calling tr.SetConnected(true) - this is the state during a reconnect.

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
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())
	if err := tr.Send([]byte("hello")); err == nil {
		t.Fatalf("expected an error before any session has ever been established")
	}
}

// --- self-echo filtering -------------------------------------------------

// TestHandleMessageDropsOwnEcho guards against Yandex's doc broadcasting our own just-sent packet back to us as if from a peer.
func TestHandleMessageDropsOwnEcho(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())

	sent := []byte("own outgoing packet bytes")
	tr.markSent(sent)

	var received [][]byte
	tr.SetEventCallback(func(string, string) {})
	tr.Receive(func(data []byte) { received = append(received, data) })

	echoMsg := `42["message",{"type":"cursor","cursor":"18;` + b64(sent) + `"}]`
	tr.handleMessage(nil, []byte(echoMsg))

	if len(received) != 0 {
		t.Fatalf("handleMessage delivered our own echoed packet to CallReceive: %v", received)
	}
}

// TestHandleMessageDeliversRealPeerData guards that the echo filter doesn't swallow genuine peer data too.
func TestHandleMessageDeliversRealPeerData(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())

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

// --- batching -------------------------------------------------------------

func buildBatch(t *testing.T, packets ...[]byte) []byte {
	t.Helper()
	var blob bytes.Buffer
	blob.WriteByte(batchMarker)
	var lenBuf [2]byte
	for _, p := range packets {
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p)))
		blob.Write(lenBuf[:])
		blob.Write(p)
	}
	return blob.Bytes()
}

// TestHandleMessageUnbatchesMultiPacketPayload guards the batched wire format: several packets carried in one WS message.
func TestHandleMessageUnbatchesMultiPacketPayload(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())

	var received [][]byte
	tr.Receive(func(data []byte) { received = append(received, append([]byte(nil), data...)) })

	pkt1 := []byte("first packet")
	pkt2 := []byte("second, a bit longer packet")
	msg := `42["message",{"type":"cursor","cursor":"18;` + b64(buildBatch(t, pkt1, pkt2)) + `"}]`
	tr.handleMessage(nil, []byte(msg))

	if len(received) != 2 || string(received[0]) != string(pkt1) || string(received[1]) != string(pkt2) {
		t.Fatalf("received = %v, want [%q %q]", received, pkt1, pkt2)
	}
}

// TestHandleMessageStillHandlesUnbatchedLegacyPayload guards backward compatibility with a peer that hasn't picked up batching yet.
func TestHandleMessageStillHandlesUnbatchedLegacyPayload(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())

	var received [][]byte
	tr.Receive(func(data []byte) { received = append(received, data) })

	legacy := []byte{0x00, 'h', 'i'} // stored marker, not batchMarker
	msg := `42["message",{"type":"cursor","cursor":"18;` + b64(legacy) + `"}]`
	tr.handleMessage(nil, []byte(msg))

	if len(received) != 1 || string(received[0]) != string(legacy) {
		t.Fatalf("received = %v, want [%q] delivered whole, unsplit", received, legacy)
	}
}

// TestHandleMessageDropsOwnEchoedBatch guards that self-echo dedup hashes the whole framed batch, not the individual packets.
func TestHandleMessageDropsOwnEchoedBatch(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())

	batch := buildBatch(t, []byte("packet a"), []byte("packet b"))
	tr.markSent(batch)

	var received [][]byte
	tr.Receive(func(data []byte) { received = append(received, data) })

	msg := `42["message",{"type":"cursor","cursor":"18;` + b64(batch) + `"}]`
	tr.handleMessage(nil, []byte(msg))

	if len(received) != 0 {
		t.Fatalf("handleMessage delivered our own echoed batch: %v", received)
	}
}

// TestWriterLoopBatchesMultiplePacketsIntoOneMessage guards that several quickly-queued packets go out as one WS message.
func TestWriterLoopBatchesMultiplePacketsIntoOneMessage(t *testing.T) {
	received := make(chan []byte, 1)
	srv := serveHandshakeServer(t, func(conn *websocket.Conn) {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		received <- msg
	})
	defer srv.Close()

	conn := dialTestServer(t, srv)
	defer conn.Close()

	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())
	if err := tr.BaseTransport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	tr.SetConnected(true)
	// Batching only turns on once the peer's keepalive has proven it understands batchMarker.
	tr.peerBatches.Store(true)
	queue := make(chan []byte, 10)
	tr.session = &DocSession{Conn: conn, WriteQueue: queue}

	go tr.writerLoop(queue)

	want := [][]byte{[]byte("aaa"), []byte("bb"), []byte("ccccc")}
	for _, p := range want {
		queue <- p
	}

	select {
	case msg := <-received:
		base64Str := tr.extractBase64String(string(msg))
		if base64Str == "" {
			t.Fatalf("could not extract a base64 payload from %q", msg)
		}
		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if len(decoded) == 0 || decoded[0] != batchMarker {
			t.Fatalf("expected a batchMarker-prefixed payload, got %v", decoded)
		}
		got := decodeBatch(decoded[1:])
		if len(got) != len(want) {
			t.Fatalf("got %d packets, want %d: %v", len(got), len(want), got)
		}
		for i := range want {
			if string(got[i]) != string(want[i]) {
				t.Errorf("packet[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("server never received the batched message")
	}
}

// TestWriterLoopDoesNotBatchByDefault guards that without proof the peer understands batchMarker, packets go out one per message.
func TestWriterLoopDoesNotBatchByDefault(t *testing.T) {
	received := make(chan []byte, 10)
	srv := serveHandshakeServer(t, func(conn *websocket.Conn) {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				return
			}
			received <- msg
		}
	})
	defer srv.Close()

	conn := dialTestServer(t, srv)
	defer conn.Close()

	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())
	if err := tr.BaseTransport.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	tr.SetConnected(true)
	queue := make(chan []byte, 10)
	tr.session = &DocSession{Conn: conn, WriteQueue: queue}

	go tr.writerLoop(queue)

	want := [][]byte{[]byte("aaa"), []byte("bb")}
	for _, p := range want {
		queue <- p
	}

	for i, w := range want {
		select {
		case msg := <-received:
			base64Str := tr.extractBase64String(string(msg))
			decoded, err := base64.StdEncoding.DecodeString(base64Str)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if len(decoded) > 0 && decoded[0] == batchMarker {
				t.Fatalf("packet %d went out batched with no peer capability proven", i)
			}
			if string(decoded) != string(w) {
				t.Errorf("packet %d = %q, want %q", i, decoded, w)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("server never received packet %d", i)
		}
	}
}

// TestHandleMessageLearnsPeerBatchingFromKeepalive guards that only a keepalive carrying kaBatchCapabilityToken sets peerBatches.
func TestHandleMessageLearnsPeerBatchingFromKeepalive(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())

	tr.handleMessage(nil, []byte(`42["message",{"type":"cursor","cursor":"18;---KA---"}]`))
	if tr.peerBatches.Load() {
		t.Fatalf("peerBatches = true after a legacy keepalive with no capability token")
	}

	tr.handleMessage(nil, []byte(`42["message",{"type":"cursor","cursor":"18;---KA---`+kaBatchCapabilityToken+`"}]`))
	if !tr.peerBatches.Load() {
		t.Fatalf("peerBatches = false after a keepalive carrying kaBatchCapabilityToken")
	}
}

// --- normalizeDocURL -------------------------------------------------

// TestNormalizeDocURLRewritesDiskShareLinks guards that a disk.yandex.ru share link is rewritten before it reaches an HTTP request.
func TestNormalizeDocURLRewritesDiskShareLinks(t *testing.T) {
	cases := map[string]string{
		"https://disk.yandex.ru/i/AbCdEfGh123":         "https://docs.yandex.ru/i/AbCdEfGh123",
		"http://disk.yandex.ru/i/xyz?foo=bar":          "http://docs.yandex.ru/i/xyz?foo=bar",
		"https://DISK.YANDEX.RU/i/CaseInsensitiveHost": "https://docs.yandex.ru/i/CaseInsensitiveHost",
		// Already a docs.yandex.ru link - must pass through byte-for-byte.
		"https://docs.yandex.ru/docs/edit?url=abc": "https://docs.yandex.ru/docs/edit?url=abc",
		// A disk.yandex.ru path that isn't a /i/ share link - left alone.
		"https://disk.yandex.ru/d/FolderShareLink": "https://disk.yandex.ru/d/FolderShareLink",
		// Malformed - returned unchanged rather than dropped.
		"not a url at all": "not a url at all",
	}
	for in, want := range cases {
		if got := normalizeDocURL(in); got != want {
			t.Errorf("normalizeDocURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNewYandexDocsTransportNormalizesDiskShareLink(t *testing.T) {
	tr := NewYandexDocsTransport("https://disk.yandex.ru/i/AbCdEfGh123", transport.DefaultConfig())
	if tr.url != "https://docs.yandex.ru/i/AbCdEfGh123" {
		t.Errorf("tr.url = %q, want the disk.yandex.ru link rewritten to docs.yandex.ru", tr.url)
	}
}

// --- backoffDelay -----------------------------------------------------

func TestBackoffDelayGrowsAndCaps(t *testing.T) {
	tr := NewYandexDocsTransport("http://example.invalid", transport.TransportConfig{
		ReconnectDelay:      100 * time.Millisecond,
		ReconnectMultiplier: 2,
		MaxReconnectDelay:   1 * time.Second,
	})

	// backoffDelay adds up to +50% jitter, so each uncapped value is checked as a range rather than an exact figure.
	assertInJitterRange(t, tr.backoffDelay(0), 100*time.Millisecond)
	assertInJitterRange(t, tr.backoffDelay(1), 200*time.Millisecond)
	assertInJitterRange(t, tr.backoffDelay(2), 400*time.Millisecond)

	if gotCapped := tr.backoffDelay(10); gotCapped != 1*time.Second {
		t.Errorf("backoffDelay(10) = %v, want capped at 1s even with jitter", gotCapped)
	}
}

func assertInJitterRange(t *testing.T, got, base time.Duration) {
	t.Helper()
	max := time.Duration(float64(base) * 1.5)
	if got < base || got > max {
		t.Errorf("got %v, want in [%v, %v] (base + 0-50%% jitter)", got, base, max)
	}
}

func TestBackoffDelayZeroWhenDisabled(t *testing.T) {
	tr := NewYandexDocsTransport("http://example.invalid", transport.TransportConfig{
		ReconnectDelay: 0,
	})
	if got := tr.backoffDelay(5); got != 0 {
		t.Errorf("backoffDelay with ReconnectDelay=0 = %v, want 0", got)
	}
}

// --- scheduleReconnect: reports a retrying event before backing off -----

func TestScheduleReconnectEmitsRetryingEvent(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.TransportConfig{
		ReconnectDelay:       5 * time.Millisecond,
		ReconnectMultiplier:  1,
		MaxReconnectAttempts: 999,
	})
	tr.BaseTransport.Start() // marks it running without spawning connectToDoc/keepAliveLoop

	var gotCode, gotDetail string
	tr.SetEventCallback(func(code, detail string) {
		gotCode, gotDetail = code, detail
		// Stop the transport so scheduleReconnect's post-sleep check bails out instead of redialing.
		tr.Stop()
	})

	tr.scheduleReconnect(2, reasonReadError, errors.New("websocket: close 1006 (abnormal closure)"))

	if gotCode != transport.EventRetrying {
		t.Fatalf("code = %q, want %q", gotCode, transport.EventRetrying)
	}
	const want = "3|0|read_error|websocket: close 1006 (abnormal closure)"
	if gotDetail != want {
		t.Errorf("detail = %q, want %q (attempt|delaySeconds|reason|cause)", gotDetail, want)
	}
}

func TestScheduleReconnectStripsNewlinesFromCause(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.TransportConfig{
		ReconnectDelay:       time.Millisecond,
		ReconnectMultiplier:  1,
		MaxReconnectAttempts: 999,
	})
	tr.BaseTransport.Start()

	var gotDetail string
	tr.SetEventCallback(func(code, detail string) {
		gotDetail = detail
		tr.Stop()
	})

	tr.scheduleReconnect(0, reasonFetchFailed, errors.New("line one\nline two"))

	if strings.Contains(gotDetail, "\n") {
		t.Errorf("detail = %q, should not contain a literal newline", gotDetail)
	}
}

func TestScheduleReconnectDoesNothingWhenNotRunning(t *testing.T) {
	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())
	// Never started - IsRunning() is false.

	called := false
	tr.SetEventCallback(func(code, detail string) { called = true })

	tr.scheduleReconnect(0, reasonDialFailed, errors.New("connection refused"))

	if called {
		t.Errorf("scheduleReconnect emitted an event even though the transport was never running")
	}
}

// --- fetchDocInfo: must never panic on a malformed page ----------------

func TestFetchDocInfoMalformedConfigReturnsErrorNotPanic(t *testing.T) {
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

			tr := NewYandexDocsTransport(srv.URL, transport.DefaultConfig())

			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("fetchDocInfo panicked: %v", r)
				}
			}()

			_, err := tr.fetchDocInfo(srv.URL, "user1")
			if err == nil {
				t.Fatalf("expected an error for malformed config, got nil")
			}
		})
	}
}

func TestFetchDocInfoValidConfig(t *testing.T) {
	body := `<script id="client-config">{"officeActionData":{"balancer_url":"https://balancer.example",` +
		`"editor_config":{"token":"tok123","document":{"key":"doc-key-1","fileType":"docx","url":"https://x/doc","title":"T"}}}}</script>`

	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.Write([]byte(body))
	}))
	defer srv.Close()

	tr := NewYandexDocsTransport(srv.URL, transport.DefaultConfig())
	info, err := tr.fetchDocInfo(srv.URL, "user1")
	if err != nil {
		t.Fatalf("fetchDocInfo: %v", err)
	}
	if info.Token != "tok123" {
		t.Errorf("Token = %q, want tok123", info.Token)
	}
	if info.DocID != "doc-key-1" {
		t.Errorf("DocID = %q, want doc-key-1", info.DocID)
	}
	if info.Host != "balancer.example" {
		t.Errorf("Host = %q, want balancer.example", info.Host)
	}
	if !strings.Contains(info.WsURL, "doc-key-1") {
		t.Errorf("WsURL = %q, want it to contain the doc key", info.WsURL)
	}

	// A request with only a bare User-Agent isn't a shape any real browser produces - itself a bot-detection signal.
	if ua := gotHeaders.Get("User-Agent"); ua != browserUserAgent {
		t.Errorf("User-Agent = %q, want %q", ua, browserUserAgent)
	}
	if gotHeaders.Get("Accept") == "" {
		t.Error("Accept header missing - real browsers always send one")
	}
	if gotHeaders.Get("Accept-Language") == "" {
		t.Error("Accept-Language header missing - real browsers always send one")
	}
}

// --- performHandshake: exercises the actual protocol sequencing fix ----

var upgrader = websocket.Upgrader{}

// serveHandshakeServer spins up a real WS server playing the Yandex side of the handshake; respond drives each test's script.
func serveHandshakeServer(t *testing.T, respond func(conn *websocket.Conn)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("server upgrade: %v", err)
			return
		}
		defer conn.Close()
		respond(conn)
	}))
}

func dialTestServer(t *testing.T, srv *httptest.Server) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func TestPerformHandshakeSuccessWaitsForAck(t *testing.T) {
	const token = "expected-token-123"
	ackSentAfterConnect := make(chan struct{}, 1)

	srv := serveHandshakeServer(t, func(conn *websocket.Conn) {
		open, _ := json.Marshal(map[string]int{"pingInterval": 25000, "pingTimeout": 5000})
		conn.WriteMessage(websocket.TextMessage, append([]byte("0"), open...))

		// Must receive the namespace-connect before sending the ack - the ordering the original bug violated.
		_, msg, err := conn.ReadMessage()
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if !strings.HasPrefix(string(msg), "40") {
			t.Errorf("expected a 40<json> namespace-connect frame, got %q", msg)
			return
		}
		var payload struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(msg[2:], &payload); err != nil {
			t.Errorf("server: bad namespace-connect payload: %v", err)
			return
		}
		if payload.Token != token {
			t.Errorf("namespace-connect token = %q, want %q", payload.Token, token)
		}

		// A mid-handshake ping - the client must answer it without mistaking it for the ack.
		conn.WriteMessage(websocket.TextMessage, []byte("2"))
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, pong, err := conn.ReadMessage()
		if err != nil || string(pong) != "3" {
			t.Errorf("expected a pong (%q) in response to the mid-handshake ping, got %q, err=%v", "3", pong, err)
		}

		close(ackSentAfterConnect)
		conn.WriteMessage(websocket.TextMessage, []byte(`40{"sid":"server-sid"}`))

		time.Sleep(50 * time.Millisecond) // let the client finish reading before we close
	})
	defer srv.Close()

	conn := dialTestServer(t, srv)
	defer conn.Close()

	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())
	readTimeout, err := tr.performHandshake(conn, token)
	if err != nil {
		t.Fatalf("performHandshake: %v", err)
	}
	if readTimeout != 30*time.Second {
		t.Errorf("readTimeout = %v, want 30s (25000+5000ms from the open packet)", readTimeout)
	}

	select {
	case <-ackSentAfterConnect:
	default:
		t.Fatalf("server never reached the point of sending the ack - performHandshake returned too early")
	}
}

func TestPerformHandshakeFailsOnConnectError(t *testing.T) {
	srv := serveHandshakeServer(t, func(conn *websocket.Conn) {
		open, _ := json.Marshal(map[string]int{"pingInterval": 25000, "pingTimeout": 20000})
		conn.WriteMessage(websocket.TextMessage, append([]byte("0"), open...))
		conn.ReadMessage() // the namespace-connect frame
		conn.WriteMessage(websocket.TextMessage, []byte(`44{"message":"not authorized"}`))
		time.Sleep(50 * time.Millisecond)
	})
	defer srv.Close()

	conn := dialTestServer(t, srv)
	defer conn.Close()

	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())
	_, err := tr.performHandshake(conn, "any-token")
	if err == nil {
		t.Fatalf("expected an error for a socket.io connect-error response")
	}
}

func TestPerformHandshakeDoesNotSendConnectBeforeOpen(t *testing.T) {
	// If the client sent its namespace-connect before the open packet arrived, this handler would see it first.
	srv := serveHandshakeServer(t, func(conn *websocket.Conn) {
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, _, err := conn.ReadMessage(); err == nil {
			t.Errorf("client sent a frame before the server's open packet was ever written")
		}
	})
	defer srv.Close()

	conn := dialTestServer(t, srv)
	defer conn.Close()

	tr := NewYandexDocsTransport("http://unused.invalid", transport.DefaultConfig())
	_, _ = tr.performHandshake(conn, "any-token") // expected to fail once the server closes; that's fine here
}
