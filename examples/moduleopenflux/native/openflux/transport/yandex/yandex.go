package yandex

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"math/rand"
	"net/http"
	neturl "net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

// Sending one WebSocket frame per queued packet was cheap enough for a
// single mobile client but scales badly on an exit node juggling many keys
// at once - every packet pays its own base64 encode, JSON string format,
// and WriteMessage syscall regardless of size, and the OS/GC overhead of
// that per-message cost is what actually dominates at higher concurrent
// packet rates, not the bytes themselves. writerLoop below batches several
// queued packets into one length-prefixed blob (the same framing Volga
// already uses - see decodeBatch in volga.go, reused here as-is) before
// base64-encoding and sending it as a single "cursor" message, the same way
// Volga batches multiple packets into one relay HTTP POST.
//
// batchMarker prefixes a batched payload's first byte so a peer can tell it
// apart from a lone compressed packet: compress() only ever emits 0x00
// (stored) or 0x1F (LZ4) as its own first byte, so 0xFE never collides with
// a real single-packet payload. That only covers RECEIVING from a mixed-
// version peer, though - see kaBatchCapabilityToken for why sending is
// gated separately.
const batchMarker = 0xFE

// kaBatchCapabilityToken rides inside the keepalive to tell a peer "my code
// understands batchMarker" before ever sending it one. Without this, a
// build that unconditionally batches breaks a not-yet-updated peer in
// EITHER role - its own receive path has no batchMarker check at all, so a
// batched frame just fails to decompress. Peer capability, not which role
// this transport plays (client vs exit node), is what writerLoop's flush
// gates sending on - see peerBatches.
const kaBatchCapabilityToken = "+batch1"

const (
	ydocsBatchSize     = 20
	ydocsBatchTimeout  = 5 * time.Millisecond
	ydocsBatchMaxBytes = 4 * 1024 * 1024
)

// wsWriteTimeout bounds every WebSocket write - without it, a stalled write
// blocks WriteMessage forever and writerLoop (the one goroutine draining a
// session's queue for its whole life) wedges there permanently.
const wsWriteTimeout = 10 * time.Second

// defaultPingWindow is used when the server's engine.io "open" packet can't
// be parsed for its own pingInterval/pingTimeout (see performHandshake) -
// 25s+20s matches Socket.IO's own common server-side defaults.
const defaultPingWindow = 45 * time.Second

// handshakeTimeout bounds how long connectToDoc waits for the engine.io
// open packet and the socket.io namespace-connect ack before giving up and
// reconnecting - see the package-level doc comment on performHandshake for
// why this handshake has to be awaited at all.
const handshakeTimeout = 15 * time.Second

// Reason codes passed to scheduleReconnect and reported as the last field of
// transport.EventRetrying's detail - see mobile.Callback.OnLogEvent and the
// Android app's Logs tab for how these map to human-readable text.
const (
	reasonFetchFailed     = "fetch_failed"
	reasonDialFailed      = "dial_failed"
	reasonHandshakeFailed = "handshake_failed"
	reasonSendFailed      = "send_failed"
	reasonReadError       = "read_error"
)

type YandexDocsInfo struct {
	CookieStr   string
	Token       string
	DocID       string
	CallbackURL string
	UserID      string
	Origin      string
	Host        string
	WsURL       string
	Permissions map[string]interface{}
	OpenCmd     map[string]interface{}
}

type DocSession struct {
	Info       YandexDocsInfo
	Conn       *websocket.Conn
	WriteQueue chan []byte
	UserID     string
	writeMu    sync.Mutex
}

func (s *DocSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.Conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
	err := s.Conn.WriteMessage(messageType, data)
	if err != nil {
		s.Conn.Close() // let the read loop notice and reconnect
	}
	return err
}

type YandexDocsTransport struct {
	*transport.BaseTransport

	url     string
	session *DocSession

	userCounter atomic.Int32
	baseUserID  string

	// recentSent guards against processing our own data. Yandex's doc
	// broadcasts every "cursor" event to every participant in the
	// document, sender included - the same self-echo a collaborative
	// editor's cursor broadcast normally is. Nothing here previously
	// checked authorship before decoding a "cursor" message and handing it
	// to CallReceive, so a tunnel packet we ourselves just sent (see
	// writerLoop) came right back over the same socket and got reinjected
	// as if the peer had sent it - a real packet, correctly formed, just
	// flowing in a direction gvisor's NAT/forwarding never expects on that
	// NIC (that's what "unexpected transport protocol = 0" turned out to
	// be a symptom of, not a cause). Recording a short-lived hash of every
	// payload we send and skipping any inbound payload that matches lets
	// this be caught without needing to know Yandex's exact broadcast
	// wrapping format, and without touching the wire format the real
	// backend expects.
	recentSentMu sync.Mutex
	recentSent   map[uint32]time.Time

	// peerBatches is learned from the peer's own keepalive (see
	// kaBatchCapabilityToken) - only once we know the peer's code
	// recognizes batchMarker do we send it batched frames, so a build
	// running against a not-yet-updated peer (or vice versa) keeps using
	// the legacy one-packet-per-message format instead of sending
	// something the other side can't parse.
	peerBatches atomic.Bool

	// wakeReconnect, guarded by Mu, is non-nil exactly while scheduleReconnect
	// is sleeping out a backoff delay between attempts - see ForceReconnect.
	wakeReconnect chan struct{}
}

func NewYandexDocsTransport(url string, config transport.TransportConfig) *YandexDocsTransport {
	t := &YandexDocsTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           normalizeDocURL(url),
	}
	t.baseUserID = randUserID()
	return t
}

// normalizeDocURL rewrites a Yandex Disk share link into the equivalent
// Yandex Docs URL fetchDocInfo actually knows how to fetch. A disk.yandex.ru
// "/i/<hash>" share link and the docs.yandex.ru edit link serve the same
// client-config-bearing page for a supported document, just under
// different hostnames - a plain host swap is all that's needed, path and
// query string carry over untouched. Used on both the client and the
// exit-node side, since both run this same transport - one normalization
// site covers whichever end of the tunnel a user pastes a disk.yandex.ru
// link into. Anything else (a different host, a malformed URL, a
// disk.yandex.ru path that isn't a share link) passes through unchanged
// and is left for the actual HTTP fetch to accept or reject.
func normalizeDocURL(raw string) string {
	u, err := neturl.Parse(raw)
	if err != nil {
		return raw
	}
	if strings.EqualFold(u.Hostname(), "disk.yandex.ru") && strings.HasPrefix(u.Path, "/i/") {
		u.Host = "docs.yandex.ru"
		return u.String()
	}
	return raw
}

func (t *YandexDocsTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.baseUserID = randUserID()
	go t.keepAliveLoop()
	t.connectToDoc(0)

	return nil
}

// Send queues data for the writer loop to actually put on the wire.
// Deliberately does not require IsConnected(): a session's WriteQueue is
// reused across a reconnect (see connectToDoc) precisely so a brief drop
// doesn't have to lose data, but an early return here for "not connected
// right now" was throwing every packet away for the entire reconnect
// window regardless - the queue existed but nothing during a drop ever
// reached it. A connection blip that would otherwise have been invisible
// (queued, then drained once the new session comes up) was instead forcing
// the real end-to-end TCP connection several hops away to notice the loss
// and retransmit on its own, much slower, timeout.
func (t *YandexDocsTransport) Send(data []byte) error {
	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()

	if session == nil {
		return fmt.Errorf("no active session")
	}

	select {
	case session.WriteQueue <- data:
		t.RecordSend(len(data))
		return nil
	default:
		return fmt.Errorf("write queue full")
	}
}

func (t *YandexDocsTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}

	utils.Debugf("[YDOCS] connectToDoc attempt %d", attempt)
	t.EmitEvent(transport.EventConnecting, strconv.Itoa(attempt+1))

	go func() {
		t.Mu.Lock()
		existingSession := t.session
		t.Mu.Unlock()

		var userID string
		if existingSession != nil {
			userID = existingSession.UserID
		} else {
			suffix := fmt.Sprintf("%03d", t.userCounter.Add(1)%1000)
			userID = t.baseUserID + suffix
		}

		info, err := t.fetchDocInfo(t.url, userID)
		if err != nil {
			utils.Debugf("[YDOCS] fetchDocInfo failed: %v", err)
			t.scheduleReconnect(attempt, reasonFetchFailed, err)
			return
		}

		dialer := websocket.Dialer{
			HandshakeTimeout:  10 * time.Second,
			EnableCompression: true, // negotiated (permessage-deflate); harmless if the server ignores it
			NetDialContext:    transport.ProtectedDialer().DialContext,
		}
		headers := http.Header{}
		headers.Set("User-Agent", browserUserAgent)
		headers.Set("Origin", info.Origin)
		headers.Set("Cookie", info.CookieStr)
		headers.Set("Host", info.Host)
		// A WebSocket upgrade, not a page load - Sec-Fetch-Dest/Mode differ
		// from applyBrowserGetHeaders' document-navigation values
		// accordingly (real Firefox sends these for a same-origin WS
		// connection opened from a page it just loaded).
		headers.Set("Sec-Fetch-Dest", "websocket")
		headers.Set("Sec-Fetch-Mode", "websocket")
		headers.Set("Sec-Fetch-Site", "same-origin")

		conn, _, err := dialer.Dial(info.WsURL, headers)
		if err != nil {
			utils.Debugf("[YDOCS] WebSocket dial failed: %v", err)
			t.scheduleReconnect(attempt, reasonDialFailed, err)
			return
		}

		// The engine.io/socket.io handshake must complete (open packet,
		// then our namespace-connect, then the server's connect ack)
		// before anything else goes over this socket. Sending the auth
		// event packet (or, worse, real tunneled data once writerLoop
		// starts draining the queue) ahead of that ack lands it in a
		// namespace the server hasn't confirmed yet, which is exactly what
		// was making OnlyOffice's backend tear the connection down with
		// close code 1005 in a loop.
		readTimeout, err := t.performHandshake(conn, info.Token)
		if err != nil {
			utils.Debugf("[YDOCS] handshake failed: %v", err)
			conn.Close()
			t.scheduleReconnect(attempt, reasonHandshakeFailed, err)
			return
		}

		writeQueue := make(chan []byte, t.GetConfig().MaxQueueSize)
		if existingSession != nil {
			writeQueue = existingSession.WriteQueue
		}

		session := &DocSession{
			Info:       info,
			Conn:       conn,
			WriteQueue: writeQueue,
			UserID:     userID,
		}

		t.Mu.Lock()
		t.session = session
		t.SetConnected(true)
		t.Mu.Unlock()

		if existingSession == nil {
			go t.writerLoop(writeQueue)
		}

		authData := map[string]interface{}{
			"type": "auth", "docid": info.DocID, "token": "fghhfgsjdgfjs",
			"user": map[string]interface{}{"id": userID}, "editorType": 0,
			"lastOtherSaveTime": -1, "permissions": info.Permissions,
			"openCmd": info.OpenCmd, "coEditingMode": "fast", "jwtOpen": info.Token,
		}
		messagePart, err := json.Marshal([]interface{}{"message", authData})
		if err != nil {
			utils.Debugf("[YDOCS] marshal auth message failed: %v", err)
			t.SetConnected(false)
			conn.Close()
			t.scheduleReconnect(attempt, reasonSendFailed, err)
			return
		}
		if err := session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart)))); err != nil {
			utils.Debugf("[YDOCS] send auth message failed: %v", err)
			t.SetConnected(false)
			conn.Close()
			t.scheduleReconnect(attempt, reasonSendFailed, err)
			return
		}
		t.EmitEvent(transport.EventConnected, strconv.Itoa(attempt+1))
		connectedAt := time.Now()

		for t.IsRunning() {
			conn.SetReadDeadline(time.Now().Add(readTimeout))
			_, message, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[YDOCS] Read error: %v", err)
				t.SetConnected(false)
				conn.Close()
				// A session that stayed up for a while dropping is a normal,
				// unremarkable blip (Yandex's own infra recycling the
				// connection, a brief network hiccup) - not evidence the
				// backend or network is struggling and reconnects should
				// slow down for. Without this, attempt only ever grows
				// across a long-lived transport's whole life, so backoff
				// eventually settles at MaxReconnectDelay and stays there
				// for every future reconnect, even hours later when nothing
				// is actually wrong - a working connection ends up waiting
				// up to 30s to come back after every routine drop.
				next := attempt
				if time.Since(connectedAt) > 15*time.Second {
					next = 0
				}
				t.scheduleReconnect(next, reasonReadError, err)
				return
			}
			t.handleMessage(session, message)
		}
	}()
}

// performHandshake waits out the engine.io/socket.io connection sequence:
//
//  1. server -> client: engine.io "open" packet ("0{...}"), carrying the
//     server's actual pingInterval/pingTimeout;
//  2. client -> server: socket.io namespace-connect ("40{"token":...}"),
//     sent only once (1) has arrived;
//  3. server -> client: namespace-connect ack ("40{"sid":...}") or a
//     connect-error ("44...") - only once the ack arrives is this socket
//     actually usable for anything else.
//
// Engine.io pings ("2") can arrive at any point in this sequence and are
// answered ("3") immediately regardless of handshake progress, same as in
// steady-state. It returns the read-idle timeout to apply for the rest of
// this connection's life (derived from the server's own ping settings so a
// silently-dead connection is detected instead of blocking forever).
func (t *YandexDocsTransport) performHandshake(conn *websocket.Conn, token string) (time.Duration, error) {
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	defer conn.SetReadDeadline(time.Time{})

	readTimeout := defaultPingWindow
	sentConnect := false

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return 0, fmt.Errorf("handshake read: %w", err)
		}
		text := string(msg)

		switch {
		case !sentConnect && strings.HasPrefix(text, "0"):
			var openPkt struct {
				PingInterval int `json:"pingInterval"`
				PingTimeout  int `json:"pingTimeout"`
			}
			if err := json.Unmarshal([]byte(text[1:]), &openPkt); err == nil &&
				openPkt.PingInterval > 0 && openPkt.PingTimeout > 0 {
				readTimeout = time.Duration(openPkt.PingInterval+openPkt.PingTimeout) * time.Millisecond
			}

			authPkt, err := json.Marshal(map[string]string{"token": token})
			if err != nil {
				return 0, fmt.Errorf("marshal namespace-connect: %w", err)
			}
			conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := conn.WriteMessage(websocket.TextMessage, append([]byte("40"), authPkt...)); err != nil {
				return 0, fmt.Errorf("send namespace-connect: %w", err)
			}
			sentConnect = true

		case text == "2":
			conn.SetWriteDeadline(time.Now().Add(wsWriteTimeout))
			if err := conn.WriteMessage(websocket.TextMessage, []byte("3")); err != nil {
				return 0, fmt.Errorf("pong during handshake: %w", err)
			}

		case strings.HasPrefix(text, "44"):
			return 0, fmt.Errorf("namespace connect rejected: %s", text)

		case sentConnect && strings.HasPrefix(text, "40"):
			return readTimeout, nil

		default:
			utils.Debugf("[YDOCS] unexpected message during handshake: %s", text)
		}
	}
}

func (t *YandexDocsTransport) writerLoop(queue chan []byte) {
	batch := make([][]byte, 0, ydocsBatchSize)
	totalBytes := 0

	flush := func(session *DocSession) {
		if len(batch) == 0 {
			return
		}
		if t.peerBatches.Load() {
			t.sendBatch(session, batch)
		} else {
			for _, pkt := range batch {
				t.sendSingle(session, pkt)
			}
		}
		batch = batch[:0]
		totalBytes = 0
	}

	for t.IsRunning() {
		// t.session is never nil'd on disconnect (see connectToDoc) - it
		// keeps pointing at the old, now-dead session until a new one
		// replaces it, so checking session/session.Conn for nil here never
		// actually catches a drop. Without also checking IsConnected(),
		// this dequeued a packet from the queue - the one piece of state
		// Send's fix relies on to survive a reconnect - and then threw it
		// away on the write to that dead connection anyway, every single
		// time. Waiting for IsConnected() before ever touching the channel
		// is what actually keeps queued data queued until a live session
		// exists to drain it into - batch (if anything is held) waits here
		// right along with it, for the same reason.
		t.Mu.RLock()
		session := t.session
		connected := t.IsConnected()
		t.Mu.RUnlock()
		if session == nil || session.Conn == nil || !connected {
			time.Sleep(50 * time.Millisecond)
			continue
		}

		select {
		case packet := <-queue:
			batch = append(batch, packet)
			totalBytes += len(packet)
			if len(batch) >= ydocsBatchSize || totalBytes >= ydocsBatchMaxBytes {
				flush(session)
			}
		case <-time.After(ydocsBatchTimeout):
			// Whatever's accumulated so far (even a single packet) goes
			// out now rather than waiting for a full batch - low traffic
			// must not turn into added latency.
			flush(session)
		}
	}
}

// sendBatch frames batch as one length-prefixed blob (batchMarker + Volga's
// own [len,data]... encoding, reused verbatim via decodeBatch on the
// receiving end), base64s it, and writes it as a single "cursor" message -
// one WriteMessage syscall and one self-echo hash for however many packets
// batch holds, instead of one of each per packet.
func (t *YandexDocsTransport) sendBatch(session *DocSession, batch [][]byte) {
	var blob bytes.Buffer
	blob.WriteByte(batchMarker)
	var lenBuf [2]byte
	for _, p := range batch {
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p)))
		blob.Write(lenBuf[:])
		blob.Write(p)
	}
	framed := blob.Bytes()

	t.markSent(framed)
	if utils.IsVerbose() {
		// framed is whatever the caller handed to Send() for each packet in
		// batch, length-prefixed and concatenated - when wrapped in
		// transport.CompressedTransport (the normal case), that's
		// already-compressed bytes, not raw IP packets, so parsing it here
		// would print convincing-looking nonsense instead of failing
		// loudly. Byte/packet counts are the only things safe to claim
		// about it at this layer.
		utils.Debugf("[YDOCS] -> %d bytes (%d packets)\n", len(framed), len(batch))
	}

	payload := base64.StdEncoding.EncodeToString(framed)
	msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)

	if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
		utils.Debugf("[YDOCS] Write error: %v", err)
	}
}

// sendSingle is sendBatch without the batchMarker framing - the exact
// one-packet-per-message format from before batching existed, used until
// the peer's keepalive proves it understands batched frames (see
// peerBatches).
func (t *YandexDocsTransport) sendSingle(session *DocSession, packet []byte) {
	t.markSent(packet)
	if utils.IsVerbose() {
		utils.Debugf("[YDOCS] -> %d bytes (unbatched)\n", len(packet))
	}

	payload := base64.StdEncoding.EncodeToString(packet)
	msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)

	if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
		utils.Debugf("[YDOCS] Write error: %v", err)
	}
}

// markSent records that data was just sent, so a later self-echo of it
// arriving back through handleMessage can be recognized and dropped - see
// YandexDocsTransport.recentSent's doc comment. Entries expire on their own
// (checked in wasRecentlySent) rather than needing an explicit size cap: an
// echo either arrives within a couple of seconds or not at all, so nothing
// legitimate is lost by letting old entries age out during opportunistic
// cleanup here.
func (t *YandexDocsTransport) markSent(data []byte) {
	h := crc32.ChecksumIEEE(data)
	now := time.Now()

	t.recentSentMu.Lock()
	defer t.recentSentMu.Unlock()
	if t.recentSent == nil {
		t.recentSent = make(map[uint32]time.Time)
	}
	t.recentSent[h] = now
	if len(t.recentSent) > 512 {
		cutoff := now.Add(-5 * time.Second)
		for k, ts := range t.recentSent {
			if ts.Before(cutoff) {
				delete(t.recentSent, k)
			}
		}
	}
}

// wasRecentlySent reports whether data matches something markSent recorded
// within the last 5 seconds - a real echo of our own traffic always arrives
// within one round trip to Yandex's servers, far under that window, while an
// unrelated packet from the peer coincidentally producing the same CRC32 is
// astronomically unlikely.
func (t *YandexDocsTransport) wasRecentlySent(data []byte) bool {
	h := crc32.ChecksumIEEE(data)

	t.recentSentMu.Lock()
	ts, ok := t.recentSent[h]
	t.recentSentMu.Unlock()

	return ok && time.Since(ts) < 5*time.Second
}

func (t *YandexDocsTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.GetConfig().KeepAliveInterval)
	defer ticker.Stop()
	// The trailing token rides inside the existing "---KA---" keepalive
	// (still an exact substring, so a not-yet-updated peer's own
	// strings.Contains(text, "---KA---") still matches and ignores it same
	// as always) - see peerBatches and kaBatchCapabilityToken.
	keepAliveMsg := `42["message",{"type":"cursor","cursor":"18;---KA---` + kaBatchCapabilityToken + `"}]`

	for t.IsRunning() {
		<-ticker.C
		t.Mu.Lock()
		session := t.session
		t.Mu.Unlock()

		if session != nil && session.Conn != nil {
			if err := session.safeWrite(websocket.TextMessage, []byte(keepAliveMsg)); err != nil {
				utils.Debugf("[YDOCS] Keep-alive failed: %v", err)
				t.SetConnected(false)
				// Force the blocked ReadMessage() in this session's read
				// loop to return immediately instead of waiting out the
				// full read-deadline window, so reconnection starts right
				// away rather than up to defaultPingWindow later.
				session.Conn.Close()
			}
		}
	}
}

func (t *YandexDocsTransport) handleMessage(session *DocSession, data []byte) {
	text := string(data)

	if strings.Contains(text, "---KA---") {
		if strings.Contains(text, kaBatchCapabilityToken) {
			t.peerBatches.Store(true)
		}
		return
	}

	// Socket.IO ping - respond with pong (use safeWrite)
	if text == "2" {
		if session != nil && session.Conn != nil {
			session.safeWrite(websocket.TextMessage, []byte("3"))
		}
		return
	}
	if text == "3" {
		return
	}

	if strings.Contains(text, "saveChanges") || strings.Contains(text, "cursor") {
		base64Str := t.extractBase64String(text)
		if base64Str == "" {
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			utils.Debugf("[YDOCS] Base64 decode error: %v", err)
			return
		}

		// The doc broadcasts every cursor event to every participant,
		// sender included - without this check our own just-sent packet
		// comes back here as if the peer had sent it. See recentSent's
		// doc comment on YandexDocsTransport for why this bit us badly:
		// it isn't a rare glitch, it's every single packet we send.
		if t.wasRecentlySent(decoded) {
			if utils.IsVerbose() {
				utils.Debugf("[YDOCS] dropped self-echo (%d bytes)\n", len(decoded))
			}
			return
		}

		if utils.IsVerbose() {
			// Same caveat as writerLoop's "-> N bytes" line: decoded is
			// still pre-decompression at this layer, not a raw IP packet.
			utils.Debugf("[YDOCS] <- %d bytes\n", len(decoded))
		}

		t.RecordReceive(len(decoded))

		// batchMarker (see sendBatch) flags decoded as several
		// length-prefixed packets rather than one lone payload - the
		// framing a not-yet-updated peer's packets never carry (compress()
		// only ever emits 0x00/0x1F as its own first byte), so this stays
		// correct talking to either version of this transport.
		if len(decoded) > 0 && decoded[0] == batchMarker {
			for _, pkt := range decodeBatch(decoded[1:]) {
				t.CallReceive(pkt)
			}
			return
		}
		t.CallReceive(decoded)
	}
}

func (t *YandexDocsTransport) extractBase64String(response string) string {
	if strings.Contains(response, "saveChanges") {
		marker := `"excelAdditionalInfo":"`
		left := strings.Index(response, marker) + len(marker)
		if left < len(marker) {
			return ""
		}
		right := strings.Index(response[left:], `"`)
		if right == -1 {
			return ""
		}
		return response[left : left+right]
	}

	re := regexp.MustCompile(`"cursor":"[^;]+;([^"]+)"`)
	matches := re.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// scheduleReconnect waits out an exponential backoff (see
// transport.DefaultConfig's ReconnectDelay/ReconnectMultiplier/
// MaxReconnectDelay) before retrying, instead of hammering the server in a
// tight loop every time a connection attempt fails fast. cause is the
// actual error that triggered this retry - reasonCode alone only tells a
// human-facing log which of a handful of fixed categories it falls into
// ("couldn't reach the document"), not what specifically went wrong; cause
// is carried in the same event for a caller that wants to show both.
func (t *YandexDocsTransport) scheduleReconnect(attempt int, reasonCode string, cause error) {
	if !t.IsRunning() || attempt >= t.GetConfig().MaxReconnectAttempts {
		return
	}

	t.RecordReconnect()

	delay := t.backoffDelay(attempt)
	causeText := strings.ReplaceAll(cause.Error(), "\n", " ")
	t.EmitEvent(transport.EventRetrying, fmt.Sprintf("%d|%d|%s|%s", attempt+1, int(delay.Seconds()), reasonCode, causeText))
	if delay > 0 {
		// wake lets ForceReconnect cut this short - published under Mu so a
		// concurrent ForceReconnect either sees it (and closes it, ending
		// the select below immediately) or arrives too early/late to matter
		// (nothing to interrupt in either case, same as before this field
		// existed).
		wake := make(chan struct{})
		t.Mu.Lock()
		t.wakeReconnect = wake
		t.Mu.Unlock()

		select {
		case <-time.After(delay):
		case <-wake:
			utils.Debugf("[YDOCS] backoff wait cut short by ForceReconnect")
		}

		t.Mu.Lock()
		if t.wakeReconnect == wake {
			t.wakeReconnect = nil
		}
		t.Mu.Unlock()
	}
	if !t.IsRunning() {
		return
	}

	t.connectToDoc(attempt + 1)
}

// ForceReconnect makes the transport retry right now: drops a live
// connection so its read loop notices and redials through the usual
// scheduleReconnect path, or, if no connection is up and it's instead
// sleeping out a backoff delay between attempts, cuts that wait short. A
// no-op if neither applies (not started yet, or already mid-attempt past
// the wait).
//
// Why this exists at all: a network change (Wi-Fi to mobile data, or back)
// often leaves the old socket silently dead rather than reset - nothing
// tells this transport's read loop the connection is gone until a read
// finally times out, which can take far longer than the backoff delay this
// skips. A caller that already knows the network changed (a mobile OS
// callback, an AntiNet-style host event) can report that here instead of
// waiting for TCP to notice on its own.
func (t *YandexDocsTransport) ForceReconnect() {
	t.Mu.Lock()
	session := t.session
	wake := t.wakeReconnect
	t.wakeReconnect = nil // claimed here, under the same lock, so a second concurrent call can't double-close wake below
	t.Mu.Unlock()

	if session != nil && session.Conn != nil {
		utils.Debugf("[YDOCS] force-reconnect: dropping live session to re-dial")
		_ = session.Conn.Close()
		return
	}
	if wake != nil {
		close(wake)
	}
}

func (t *YandexDocsTransport) backoffDelay(attempt int) time.Duration {
	cfg := t.GetConfig()
	if cfg.ReconnectDelay <= 0 {
		return 0
	}

	multiplier := cfg.ReconnectMultiplier
	if multiplier < 1 {
		multiplier = 1
	}

	delay := float64(cfg.ReconnectDelay) * math.Pow(multiplier, float64(attempt))
	// +0-50% jitter, applied before the cap so MaxReconnectDelay stays a
	// true ceiling: every reconnect dials a brand new WebSocket, which
	// Yandex's own doc-collab backend registers as a brand new participant
	// in the room regardless of client-side user-id reuse (ported from
	// upstream p1neappleXpress/OpenFlux, which found this live - "ghost"
	// participants piling up across a failure streak, logged from the
	// server's own participant-list messages). Without jitter, many clients
	// losing the same document at once (a network-wide blip, an exit-node
	// restart) would retry in lockstep at identical delays instead of
	// spreading out.
	delay += delay * 0.5 * rand.Float64()
	if cfg.MaxReconnectDelay > 0 && delay > float64(cfg.MaxReconnectDelay) {
		delay = float64(cfg.MaxReconnectDelay)
	}
	return time.Duration(delay)
}

func (t *YandexDocsTransport) fetchDocInfo(url, userID string) (YandexDocsInfo, error) {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil },
		Timeout:       30 * time.Second,
		Transport:     &http.Transport{DialContext: transport.ProtectedDialer().DialContext},
	}

	req, _ := http.NewRequest("GET", url, nil)
	applyBrowserGetHeaders(req.Header)
	resp, err := client.Do(req)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	defer resp.Body.Close()

	htmlBytes, _ := io.ReadAll(resp.Body)
	html := string(htmlBytes)

	utils.Debugf("[YDOCS] fetchDocInfo GET %s -> %d (%d bytes)", url, resp.StatusCode, len(html))

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}

	re := regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) < 2 {
		// Without this, "config not found" was a dead end - no way to tell
		// a CAPTCHA page apart from a login redirect, a maintenance page,
		// or something else entirely without reproducing it by hand.
		// SmartCaptcha/showcaptcha/checkbox-captcha are the markers Yandex's
		// own bot-check pages actually use, so this is flagged explicitly
		// rather than left for someone reading the preview to notice.
		lower := strings.ToLower(html)
		if strings.Contains(lower, "captcha") {
			utils.Debugf("[YDOCS] response looks like a CAPTCHA/bot-check page, not the doc editor")
		}
		preview := html
		if len(preview) > 2000 {
			preview = preview[:2000]
		}
		utils.Debugf("[YDOCS] HTML preview: %s", preview)
		return YandexDocsInfo{}, fmt.Errorf("config not found")
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return YandexDocsInfo{}, fmt.Errorf("parse client-config: %w", err)
	}

	// Every lookup below used to be an unchecked type assertion
	// (config["x"].(T)), which panics - and since this runs in a goroutine
	// with no recover(), crashes the entire process - the moment Yandex
	// serves a page shaped even slightly differently than expected (an
	// error/maintenance page, an A/B-tested layout, a partly-loaded
	// response). All of it is now checked and turned into a plain error
	// that triggers a reconnect instead.
	officeAction, ok := config["officeActionData"].(map[string]interface{})
	if !ok {
		utils.Debugf("[YDOCS] config top-level keys: %v", mapKeys(config))
		return YandexDocsInfo{}, fmt.Errorf("officeActionData missing or malformed")
	}

	editorConfigRaw, ok := officeAction["editor_config"].(map[string]interface{})
	if !ok || editorConfigRaw == nil {
		utils.Debugf("[YDOCS] officeActionData keys: %v", mapKeys(officeAction))
		return YandexDocsInfo{}, fmt.Errorf("editor_config nil - will reconnect")
	}

	balancerURL, ok := officeAction["balancer_url"].(string)
	if !ok {
		// Confirmed in production: this exact signature (officeActionData +
		// editor_config both present, only balancer_url missing - not a
		// captcha or error page, which would fail the "config not found"
		// check above instead) is what a newer-generation Yandex document
		// looks like to this transport. This transport (the classic
		// engine.io/socket.io editor session docs.yandex.ru serves) doesn't
		// know how to talk to those; YandexVolgaTransport does (a different
		// auth flow entirely - see volga.go's authorize()). There's no way
		// to tell a document is this type before hitting this error - it's
		// specific to the individual doc, not the URL shape - so the best
		// this can do is name the actual fix instead of a bare parse error.
		utils.Debugf("[YDOCS] officeActionData keys: %v, editor_config keys: %v", mapKeys(officeAction), mapKeys(editorConfigRaw))
		return YandexDocsInfo{}, fmt.Errorf("balancer_url missing - this document looks like a newer Yandex Docs type this transport doesn't support; try the Volga transport for this doc_url instead")
	}
	host := strings.TrimPrefix(balancerURL, "https://")

	document, ok := editorConfigRaw["document"].(map[string]interface{})
	if !ok {
		utils.Debugf("[YDOCS] editor_config keys: %v", mapKeys(editorConfigRaw))
		return YandexDocsInfo{}, fmt.Errorf("document missing or malformed")
	}

	token, ok := editorConfigRaw["token"].(string)
	if !ok {
		utils.Debugf("[YDOCS] editor_config keys: %v", mapKeys(editorConfigRaw))
		return YandexDocsInfo{}, fmt.Errorf("editor_config.token missing or malformed")
	}

	docKey, ok := document["key"].(string)
	if !ok {
		utils.Debugf("[YDOCS] document keys: %v", mapKeys(document))
		return YandexDocsInfo{}, fmt.Errorf("document.key missing or malformed")
	}

	perms, _ := document["permissions"].(map[string]interface{})
	if perms == nil {
		perms = make(map[string]interface{})
	}

	return YandexDocsInfo{
		CookieStr:   strings.Join(cookies, "; "),
		Token:       token,
		DocID:       docKey,
		Origin:      balancerURL,
		Host:        host,
		WsURL:       fmt.Sprintf("wss://%s/2024.1.1-375/doc/%s/c/?EIO=4&transport=websocket", host, docKey),
		Permissions: perms,
		OpenCmd: map[string]interface{}{
			"c":      "open",
			"id":     docKey,
			"userid": userID,
			"format": document["fileType"],
			"url":    document["url"],
			"title":  document["title"],
			"lcid":   25,
		},
	}, nil
}

func randUserID() string {
	return fmt.Sprintf("%010d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000000))
}
