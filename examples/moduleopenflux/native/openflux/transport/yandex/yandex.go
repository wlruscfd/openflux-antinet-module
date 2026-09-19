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

// batchMarker flags a batched payload's first byte; compress() never emits 0xFE as a lone packet's first byte, so the two can't collide.
const batchMarker = 0xFE

// kaBatchCapabilityToken tells a peer via keepalive that it understands batchMarker before we ever send one - see peerBatches.
const kaBatchCapabilityToken = "+batch1"

const (
	ydocsBatchSize     = 20
	ydocsBatchTimeout  = 5 * time.Millisecond
	ydocsBatchMaxBytes = 4 * 1024 * 1024
)

// wsWriteTimeout bounds every WebSocket write so a stalled write can't wedge writerLoop forever.
const wsWriteTimeout = 10 * time.Second

// defaultPingWindow is used when the open packet's ping settings can't be parsed; matches Socket.IO's common defaults.
const defaultPingWindow = 45 * time.Second

// handshakeTimeout bounds how long connectToDoc waits for the handshake before giving up and reconnecting.
const handshakeTimeout = 15 * time.Second

// Reason codes reported in transport.EventRetrying's detail; see the Android app's Logs tab.
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

	// recentSent guards against reprocessing our own data: Yandex echoes every "cursor" event back to its sender too.
	recentSentMu sync.Mutex
	recentSent   map[uint32]time.Time

	// peerBatches is learned from the peer's keepalive (kaBatchCapabilityToken); only then do we send it batched frames.
	peerBatches atomic.Bool

	// wakeReconnect, guarded by Mu, is non-nil exactly while scheduleReconnect sleeps out a backoff delay - see ForceReconnect.
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

// normalizeDocURL rewrites a disk.yandex.ru share link to the equivalent docs.yandex.ru URL fetchDocInfo expects.
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

// Send doesn't require IsConnected(): WriteQueue survives a reconnect, so a brief drop just queues data instead of surfacing as loss.
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
		// A WebSocket upgrade, not a page load, so Sec-Fetch-* differ from applyBrowserGetHeaders' values.
		headers.Set("Sec-Fetch-Dest", "websocket")
		headers.Set("Sec-Fetch-Mode", "websocket")
		headers.Set("Sec-Fetch-Site", "same-origin")

		conn, _, err := dialer.Dial(info.WsURL, headers)
		if err != nil {
			utils.Debugf("[YDOCS] WebSocket dial failed: %v", err)
			t.scheduleReconnect(attempt, reasonDialFailed, err)
			return
		}

		// The handshake must complete before anything else goes over this socket - sending early got connections torn down with close code 1005.
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
				// A session that stayed up a while before dropping is a normal blip, not sustained trouble, so reset backoff.
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

// performHandshake waits for the engine.io open packet, sends the namespace-connect, then waits for its ack before the socket is usable.
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
		// t.session is never nil'd on disconnect, so only IsConnected() (not a nil check) tells a live session from a stale pointer.
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
			// Flush whatever's accumulated now rather than waiting for a full batch, so low traffic doesn't add latency.
			flush(session)
		}
	}
}

// sendBatch frames batch as one length-prefixed blob and sends it as a single message instead of one per packet.
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
		// framed is already-compressed bytes at this layer, not raw IP packets - only byte/packet counts are safe to log here.
		utils.Debugf("[YDOCS] -> %d bytes (%d packets)\n", len(framed), len(batch))
	}

	payload := base64.StdEncoding.EncodeToString(framed)
	msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)

	if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
		utils.Debugf("[YDOCS] Write error: %v", err)
	}
}

// sendSingle is sendBatch without batchMarker framing, used until the peer's keepalive proves it understands batched frames.
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

// markSent records a short-lived hash of sent data so a later self-echo can be recognized and dropped.
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

// wasRecentlySent reports whether data was sent within the last 5s - a real echo always arrives far under that window.
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
	// The capability token rides inside the existing "---KA---" keepalive so a stale peer's substring match still ignores it.
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
				// Force the blocked read to return now instead of waiting out the full read-deadline window.
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

	// Socket.IO ping - respond with pong
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

		// The doc broadcasts every cursor event back to its sender too, so our own just-sent packet would otherwise loop back here.
		if t.wasRecentlySent(decoded) {
			if utils.IsVerbose() {
				utils.Debugf("[YDOCS] dropped self-echo (%d bytes)\n", len(decoded))
			}
			return
		}

		if utils.IsVerbose() {
			utils.Debugf("[YDOCS] <- %d bytes\n", len(decoded))
		}

		t.RecordReceive(len(decoded))

		// batchMarker flags decoded as several length-prefixed packets rather than one lone payload.
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

// scheduleReconnect waits out an exponential backoff before retrying instead of hammering the server on every failed attempt.
func (t *YandexDocsTransport) scheduleReconnect(attempt int, reasonCode string, cause error) {
	if !t.IsRunning() || attempt >= t.GetConfig().MaxReconnectAttempts {
		return
	}

	t.RecordReconnect()

	delay := t.backoffDelay(attempt)
	causeText := strings.ReplaceAll(cause.Error(), "\n", " ")
	t.EmitEvent(transport.EventRetrying, fmt.Sprintf("%d|%d|%s|%s", attempt+1, int(delay.Seconds()), reasonCode, causeText))
	if delay > 0 {
		// wake lets ForceReconnect cut this short; published under Mu so a concurrent call can't race it.
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

// ForceReconnect retries now: drops a live connection to redial, or cuts short a backoff sleep if one is in progress.
func (t *YandexDocsTransport) ForceReconnect() {
	t.Mu.Lock()
	session := t.session
	live := t.IsConnected()
	wake := t.wakeReconnect
	t.wakeReconnect = nil // claimed here, under the same lock, so a second concurrent call can't double-close wake below
	t.Mu.Unlock()

	if live && session != nil && session.Conn != nil {
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
	// +0-50% jitter, applied before the cap, so many clients failing at once don't retry in lockstep.
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
		// Flag CAPTCHA pages explicitly so they're not mistaken for a login redirect or other failure.
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

	// Every lookup below is checked, not a bare type assertion - this runs in a goroutine with no recover().
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
		// balancer_url missing (but officeActionData/editor_config present) means a newer Yandex Docs type this transport can't handle.
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
