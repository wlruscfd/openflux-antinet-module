package yandex

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
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
	return s.Conn.WriteMessage(messageType, data)
}

type YandexDocsTransport struct {
	*transport.BaseTransport

	url     string
	session *DocSession

	userCounter atomic.Int32
	baseUserID  string

	// dial — чем этот транспорт дозванивается (HTTP-GET документа + WebSocket). См. transport/dial.go.
	dial transport.DialContextFunc

	// recentSent — защита от собственного эха. Документ Яндекса рассылает КАЖДОЕ событие
	// "cursor"/"saveChanges" ВСЕМ участникам, включая отправителя, поэтому пакет, который этот же
	// транспорт только что отправил (см. writerLoop), возвращается по тому же сокету и без этой
	// проверки handleMessage скармливал его в CallReceive неотличимо от настоящих данных пира -
	// собственный исходящий пакет реинжектился в собственный туннель. Портировано из
	// openflux-server (сестринский проект этого модуля), где это оказалось причиной "unexpected
	// transport protocol = 0" на стороне exit-node - паника была СЛЕДСТВИЕМ, а не причиной: пакет
	// был вполне валиден, просто шёл не в том направлении, которого gVisor NAT/forwarding ждёт от
	// этого NIC. Хранится короткоживущий CRC32 всего отправленного; совпадение с этим списком в
	// течение нескольких секунд - однозначный признак эха, а не совпадения с данными пира.
	recentSentMu sync.Mutex
	recentSent   map[uint32]time.Time
}

func NewYandexDocsTransport(url string, config transport.TransportConfig, dial transport.DialContextFunc) *YandexDocsTransport {
	t := &YandexDocsTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           url,
		dial:          dial,
	}
	t.baseUserID = randUserID()
	return t
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
// doesn't have to lose data - an early return here for "not connected right
// now" would throw every packet away for the entire reconnect window
// regardless, forcing the real end-to-end TCP connection several hops away
// to notice the loss and retransmit on its own, much slower, timeout
// instead of the drop being invisible (queued, then drained once the new
// session comes up). See writerLoop's doc comment for the other half of
// this: the queue only actually helps if writerLoop waits for a live
// session before draining it.
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
			t.scheduleReconnect(attempt)
			return
		}

		dialer := transport.NewWSDialer(t.dial, 10*time.Second)
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0")
		headers.Set("Origin", info.Origin)
		headers.Set("Cookie", info.CookieStr)
		headers.Set("Host", info.Host)

		conn, _, err := dialer.Dial(info.WsURL, headers)
		if err != nil {
			utils.Debugf("[YDOCS] WebSocket dial failed: %v", err)
			t.scheduleReconnect(attempt)
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
			go t.writerLoop()
		}

		// Auth - use safeWrite
		auth1 := fmt.Sprintf(`40{"token":"%s"}`, info.Token)
		session.safeWrite(websocket.TextMessage, []byte(auth1))

		authData := map[string]interface{}{
			"type": "auth", "docid": info.DocID, "token": "fghhfgsjdgfjs",
			"user": map[string]interface{}{"id": userID}, "editorType": 0,
			"lastOtherSaveTime": -1, "permissions": info.Permissions,
			"openCmd": info.OpenCmd, "coEditingMode": "fast", "jwtOpen": info.Token,
		}
		messagePart, _ := json.Marshal([]interface{}{"message", authData})
		session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart))))

		connectedAt := time.Now()
		for t.IsRunning() {
			_, message, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[YDOCS] Read error: %v", err)
				t.SetConnected(false)
				// A session that stayed up for a while before dropping is a
				// normal, unremarkable blip (Yandex's own infra recycling
				// the connection, a brief network hiccup) - not evidence
				// the backend or network is struggling and reconnects
				// should slow down for. Without this, attempt only ever
				// grows across a long-lived transport's whole life, so
				// backoff eventually settles at MaxReconnectDelay and stays
				// there for every future reconnect, even hours later when
				// nothing is actually wrong.
				next := attempt
				if time.Since(connectedAt) > 15*time.Second {
					next = 0
				}
				t.scheduleReconnect(next)
				return
			}
			t.handleMessage(session, message)
		}
	}()
}

func (t *YandexDocsTransport) writerLoop() {
	for t.IsRunning() {
		// t.session is never nil'd on disconnect (see connectToDoc) - it
		// keeps pointing at the old, now-dead session until a new one
		// replaces it, so checking session/session.Conn for nil here never
		// actually catches a drop. Without also checking IsConnected(),
		// this would dequeue a packet from the queue - the one piece of
		// state Send's doc comment relies on to survive a reconnect - and
		// throw it away on the write to that dead connection anyway, every
		// single time. Waiting for IsConnected() before ever touching the
		// channel is what actually keeps queued data queued until a live
		// session exists to drain it into.
		t.Mu.Lock()
		session := t.session
		connected := t.IsConnected()
		t.Mu.Unlock()

		if session == nil || session.Conn == nil || !connected {
			time.Sleep(10 * time.Millisecond)
			continue
		}

		select {
		case packet := <-session.WriteQueue:
			t.markSent(packet)

			payload := base64.StdEncoding.EncodeToString(packet)
			msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)

			if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
				utils.Debugf("[YDOCS] Write error: %v", err)
			}
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (t *YandexDocsTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.GetConfig().KeepAliveInterval)
	defer ticker.Stop()
	keepAliveMsg := `42["message",{"type":"cursor","cursor":"18;---KA---"}]`

	for t.IsRunning() {
		<-ticker.C
		t.Mu.Lock()
		session := t.session
		t.Mu.Unlock()

		if session != nil && session.Conn != nil {
			if err := session.safeWrite(websocket.TextMessage, []byte(keepAliveMsg)); err != nil {
				utils.Debugf("[YDOCS] Keep-alive failed: %v", err)
				t.SetConnected(false)
			}
		}
	}
}

func (t *YandexDocsTransport) handleMessage(session *DocSession, data []byte) {
	text := string(data)

	if strings.Contains(text, "---KA---") {
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

		// See recentSent's doc comment on YandexDocsTransport: the doc
		// broadcasts every cursor event to every participant, sender
		// included, so this bit us badly - it isn't a rare glitch, it's
		// every single packet this transport sends.
		if t.wasRecentlySent(decoded) {
			return
		}

		t.RecordReceive(len(decoded))
		t.CallReceive(decoded)
	}
}

// markSent records that data was just sent, so a later self-echo of it
// arriving back through handleMessage can be recognized and dropped - see
// YandexDocsTransport.recentSent's doc comment. Entries expire on their own
// (checked in wasRecentlySent) rather than needing an explicit size cap: an
// echo either arrives within a couple of seconds or not at all.
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

func (t *YandexDocsTransport) scheduleReconnect(attempt int) {
	if !t.IsRunning() || attempt >= t.GetConfig().MaxReconnectAttempts {
		return
	}

	t.RecordReconnect()

	delay := t.backoffDelay(attempt)
	if delay > 0 {
		time.Sleep(delay)
	}
	if !t.IsRunning() {
		return
	}

	t.connectToDoc(attempt + 1)
}

// backoffDelay returns an exponential backoff (ReconnectDelay *
// ReconnectMultiplier^attempt, capped at MaxReconnectDelay) so a failing
// connection retries with real, growing delays instead of hammering the
// document/exit-node in a tight loop.
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
	if cfg.MaxReconnectDelay > 0 && delay > float64(cfg.MaxReconnectDelay) {
		delay = float64(cfg.MaxReconnectDelay)
	}
	return time.Duration(delay)
}

func (t *YandexDocsTransport) fetchDocInfo(url, userID string) (YandexDocsInfo, error) {
	client := transport.NewHTTPClient(t.dial, 30*time.Second)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	defer resp.Body.Close()

	htmlBytes, _ := io.ReadAll(resp.Body)
	html := string(htmlBytes)

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}

	re := regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) < 2 {
		return YandexDocsInfo{}, fmt.Errorf("config not found")
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return YandexDocsInfo{}, fmt.Errorf("parse client-config: %w", err)
	}

	// Every lookup below used to be an unchecked type assertion
	// (config["x"].(T)), which panics - and since this runs in a goroutine
	// with no recover(), crashes the entire helper process - the moment
	// Yandex serves a page shaped even slightly differently than expected
	// (an error/maintenance page, an A/B-tested layout, a partly-loaded
	// response, someone else with the same doc open triggering a
	// view-only fallback). All of it is now checked and turned into a
	// plain error that triggers a reconnect instead.
	officeAction, ok := config["officeActionData"].(map[string]interface{})
	if !ok {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData missing or malformed")
	}

	editorConfigRaw, ok := officeAction["editor_config"].(map[string]interface{})
	if !ok || editorConfigRaw == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config nil - will reconnect")
	}

	balancerURL, ok := officeAction["balancer_url"].(string)
	if !ok {
		return YandexDocsInfo{}, fmt.Errorf("balancer_url missing or malformed")
	}
	host := strings.TrimPrefix(balancerURL, "https://")

	document, ok := editorConfigRaw["document"].(map[string]interface{})
	if !ok {
		return YandexDocsInfo{}, fmt.Errorf("document missing or malformed")
	}

	token, ok := editorConfigRaw["token"].(string)
	if !ok {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.token missing or malformed")
	}

	docKey, ok := document["key"].(string)
	if !ok {
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
