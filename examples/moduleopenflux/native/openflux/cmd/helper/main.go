// SPDX-License-Identifier: GPL-3.0-or-later

// OpenFlux AntiNet protocol-module helper; realMain and moduleCall are the two required exports.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/oneme"
	"universal-bypass-tool/transport/yandex"
	"universal-bypass-tool/tunnel"
	"universal-bypass-tool/utils"
)

// Link grammar: openflux://yandex?url=...[#Name] | openflux://oneme?token=...&uid=...[#Name] | openflux://import?data=<base64url JSON>.
const (
	linkScheme       = "openflux"
	linkHostImport   = "import" // openflux://import?data=... — см. decodeImportLink
	transportYandex  = "yandex"
	transportOneMe   = "oneme"
	transportVolga   = "volga" // распознаётся, но пока не портирован в этот модуль — см. decodeImportLink
	defaultDialSec   = 15
	defaultKeepSec   = 10
	readyWaitBudget  = 90 * time.Second // см. waitTransportUp
	transportUpPoll  = 200 * time.Millisecond
	dnsQueryFamilyV4 = 4
)

// User-facing text after PROGRESS|/LOG| tags must be in APP_LANG (MODULE_API §2.9); tags and log.Printf stay ASCII/English.
type ofStrings struct {
	badLinkFmt              string // %v — ошибка разбора
	openingTransportFmt     string // %s — имя транспорта
	transportStartFailedFmt string // %v — ошибка
	transportNotUpFmt       string // %s — бюджет ожидания
	socksListenFailedFmt    string // %v — ошибка
	writeReadyFailedFmt     string // %v — ошибка
	socksUpFmt              string // %d — порт
	handoverLog             string
}

var ofStringsRU = ofStrings{
	badLinkFmt:              "OpenFlux: неверная ссылка: %v",
	openingTransportFmt:     "OpenFlux: открываю транспорт %s",
	transportStartFailedFmt: "OpenFlux: транспорт не стартовал: %v",
	transportNotUpFmt:       "OpenFlux: транспорт не поднялся за %s — выходим, чтобы хост перезапустил",
	socksListenFailedFmt:    "OpenFlux: не удалось взять SOCKS-листенер: %v",
	writeReadyFailedFmt:     "OpenFlux: не удалось записать маркер готовности: %v — выходим, чтобы хост перезапустил",
	socksUpFmt:              "OpenFlux: SOCKS5 поднят на 127.0.0.1:%d",
	handoverLog:             "хендовер: сменилась сеть — переподключаю транспорт",
}

var ofStringsEN = ofStrings{
	badLinkFmt:              "OpenFlux: bad link: %v",
	openingTransportFmt:     "OpenFlux: opening %s transport",
	transportStartFailedFmt: "OpenFlux: transport start failed: %v",
	transportNotUpFmt:       "OpenFlux: transport did not come up within %s - exiting so the host can restart",
	socksListenFailedFmt:    "OpenFlux: SOCKS listener failed: %v",
	writeReadyFailedFmt:     "OpenFlux: failed to mark readiness: %v - exiting so the host can restart",
	socksUpFmt:              "OpenFlux: SOCKS5 up on 127.0.0.1:%d",
	handoverLog:             "handover: network changed, reconnecting transport",
}

// ofStringsFor — APP_LANG "ru" → русский стол, всё остальное (в т.ч. пусто/неизвестно) → английский.
func ofStringsFor(lang string) ofStrings {
	if strings.EqualFold(strings.TrimSpace(lang), "ru") {
		return ofStringsRU
	}
	return ofStringsEN
}

// openFluxLink is a parsed link; fields mirror upstream's CLI flags one-to-one.
type openFluxLink struct {
	Transport string // yandex | oneme
	URL       string // yandex: адрес документа
	Token     string // oneme: токен MAX
	UID       int64  // oneme: id собеседника (exit-node)
	Name      string // фрагмент ссылки — имя для карточки конфига
}

// parseOpenFluxLink is the single link decoder shared by the connect path, summarize, and normalize.
func parseOpenFluxLink(raw string) (openFluxLink, error) {
	var l openFluxLink
	s := strings.TrimSpace(raw)
	if s == "" {
		return l, fmt.Errorf("empty link")
	}
	u, err := url.Parse(s)
	if err != nil {
		return l, fmt.Errorf("parse %q: %w", s, err)
	}
	if !strings.EqualFold(u.Scheme, linkScheme) {
		return l, fmt.Errorf("not an %s:// link", linkScheme)
	}

	host := strings.ToLower(strings.TrimSpace(u.Host))
	l.Name = strings.TrimSpace(u.Fragment)
	q := u.Query()

	// The import form unwraps to the same {Transport, URL, Name} shape the plain yandex/oneme forms produce.
	if host == linkHostImport {
		tr, docURL, name, derr := decodeImportLink(q)
		if derr != nil {
			return l, derr
		}
		if name != "" {
			l.Name = name
		}
		host = tr
		l.URL = docURL
	}

	l.Transport = host
	switch l.Transport {
	case transportYandex:
		if l.URL == "" { // not already set by decodeImportLink above
			l.URL = strings.TrimSpace(q.Get("url"))
		}
		if l.URL == "" {
			return l, fmt.Errorf("%s: missing url=", transportYandex)
		}
	case transportOneMe:
		l.Token = strings.TrimSpace(q.Get("token"))
		if l.Token == "" {
			return l, fmt.Errorf("%s: missing token=", transportOneMe)
		}
		uid, cerr := strconv.ParseInt(strings.TrimSpace(q.Get("uid")), 10, 64)
		if cerr != nil || uid == 0 {
			return l, fmt.Errorf("%s: missing or malformed uid=", transportOneMe)
		}
		l.UID = uid
	case transportVolga:
		return l, fmt.Errorf("%s: transport not supported by this module build yet", transportVolga)
	default:
		return l, fmt.Errorf("unknown transport %q (want %s|%s)", l.Transport, transportYandex, transportOneMe)
	}
	return l, nil
}

// decodeImportLink never dials control_url - that request would hit a bare IP with none of the tunnel's disguise.
func decodeImportLink(q url.Values) (transportName, docURL, name string, err error) {
	raw, derr := base64.RawURLEncoding.DecodeString(q.Get("data"))
	if derr != nil {
		return "", "", "", fmt.Errorf("import: bad data= (%w)", derr)
	}
	var m map[string]any
	if jerr := json.Unmarshal(raw, &m); jerr != nil {
		return "", "", "", fmt.Errorf("import: data= is not JSON (%w)", jerr)
	}
	str := func(k string) string {
		v, _ := m[k].(string)
		return strings.TrimSpace(v)
	}

	transportName = strings.ToLower(str("transport"))
	if transportName == "" {
		transportName = transportYandex // openflux-server's own default (mobile.buildTransport)
	}
	if transportName != transportYandex && transportName != transportVolga {
		return "", "", "", fmt.Errorf("import: unsupported transport %q", transportName)
	}

	docURL = str("doc_url")
	if docURL == "" {
		return "", "", "", fmt.Errorf("import: missing doc_url")
	}
	return transportName, docURL, str("name"), nil
}

// server is the config card's "server" field; two configs of the same transport must differ here.
func (l openFluxLink) server() string {
	if l.Transport == transportYandex {
		if u, err := url.Parse(l.URL); err == nil && u.Host != "" {
			return u.Host
		}
		return l.URL
	}
	return "max.ru:" + strconv.FormatInt(l.UID, 10)
}

func (l openFluxLink) displayName() string {
	if l.Name != "" {
		return l.Name
	}
	if l.Transport == transportYandex {
		return "OpenFlux Yandex"
	}
	return "OpenFlux MAX"
}

// normalizeOpenFlux converts non-link JSON forms to a canonical openflux://-link (MODULE_API §2.6).
func normalizeOpenFlux(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(strings.ToLower(s), linkScheme+"://") {
		return ""
	}
	if !strings.HasPrefix(s, "{") {
		return "" // no base64 wrapper support - the format has no signature to tell it apart from another module's data
	}
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return ""
	}
	str := func(k string) string {
		v, _ := m[k].(string)
		return strings.TrimSpace(v)
	}
	tr := strings.ToLower(str("transport"))
	q := url.Values{}
	switch tr {
	case transportYandex:
		if str("url") == "" {
			return ""
		}
		q.Set("url", str("url"))
	case transportOneMe:
		uid := str("uid")
		if uid == "" {
			if f, ok := m["uid"].(float64); ok {
				uid = strconv.FormatInt(int64(f), 10)
			}
		}
		if str("token") == "" || uid == "" {
			return ""
		}
		q.Set("token", str("token"))
		q.Set("uid", uid)
	default:
		return ""
	}
	link := linkScheme + "://" + tr + "?" + q.Encode()
	if n := str("name"); n != "" {
		link += "#" + url.PathEscape(n)
	}
	return link
}

// moduleCall handles parse-only subcommands (MODULE_API §2.2); shared by argv (desktop) and antinet_module_call (Android).
func moduleCall(verb, arg string) string {
	switch verb {
	case "summarize":
		l, err := parseOpenFluxLink(arg)
		if err != nil {
			return "\n" // bad/foreign link - host keeps the placeholder
		}
		return l.displayName() + "\n" + l.server()
	case "normalize":
		return normalizeOpenFlux(arg)
	}
	return ""
}

// ── Тело модуля ───────────────────────────────────────────────────────────────────────────────

func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int {
	_ = resolversPath // OpenFlux не использует: его транспорт настраивается ссылкой целиком

	// Host event channel must start first (desktop: line-based stdin; Android: no-op).
	startHostEventReader()
	dieWithParent()
	protectFromOomKill()
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	cfg := parseConfig(configContent)
	s := ofStringsFor(cfg["APP_LANG"])          // §2.9: текст для юзера — на языке AntiNet
	port, _ := strconv.Atoi(cfg["LISTEN_PORT"]) // 0 = эфемерный (ядро выберет)
	user := cfg["SOCKS_USER"]
	pass := cfg["SOCKS_PASS"]

	if cfg["SETTING_debugLog"] == "true" {
		utils.EnableDebug() // апстримный `-debug`: подробный лог транспорта и туннеля
	}

	link, err := parseOpenFluxLink(cfg["LINK"])
	if err != nil {
		// The failure reason must reach the host explicitly via LOG|/STATUS|, not just "module failed to start".
		emitLog(s.badLinkFmt, err)
		emitStatus(statusFatal, "bad link")
		log.Fatalf("parse LINK: %v", err)
	}

	dialTimeout := settingDuration(cfg, "SETTING_dialTimeoutSec", defaultDialSec)
	keepAlive := settingDuration(cfg, "SETTING_keepAliveSec", defaultKeepSec)

	// SOCKS5 CONNECT targets resolve via this protected, TTL-cached, single-flight resolver.
	resolver := newProtectedResolver(cfg["DNS_SERVERS"], protectPath)

	// The transport's own dial/resolve is set globally (transport/protect.go); yandex.go/oneme call it themselves.
	transport.SetProtector(func(fd int) bool { return protectFdFunc(protectPath)(int32(fd)) })
	if servers := hostDNSServers(cfg["DNS_SERVERS"]); len(servers) > 0 {
		transport.SetBootstrapDNSServers(servers)
	}
	net.DefaultResolver = transport.ProtectedResolver()

	tcfg := transport.DefaultConfig()
	if keepAlive > 0 {
		tcfg.KeepAliveInterval = keepAlive
	}

	var trans transport.Transport
	var hoTransport handoverer
	switch link.Transport {
	case transportYandex:
		yt := yandex.NewYandexDocsTransport(link.URL, tcfg)
		trans = transport.NewCompressedTransport(yt)
		hoTransport = yt
	default:
		ot := oneme.NewOneMeTransport(false, link.Token, link.UID, tcfg)
		trans = transport.NewCompressedTransport(ot)
		hoTransport = ot
	}

	emitProgress(s.openingTransportFmt, link.Transport)
	if err := trans.Start(); err != nil {
		emitLog(s.transportStartFailedFmt, err)
		emitStatus(statusFatal, "transport start failed")
		log.Fatalf("transport start: %v", err)
	}

	// The ready marker means "traffic can flow", so it's only written after the transport actually comes up.
	if !waitTransportUp(trans) {
		// A clean exit here lets the host's death-watchdog restart us immediately instead of waiting out the full budget.
		emitLog(s.transportNotUpFmt, readyWaitBudget)
		emitStatus(statusFatal, "transport did not come up")
		log.Fatalf("transport did not come up within %s", readyWaitBudget)
	}

	tun := tunnel.NewTCPTunnel(trans)

	ln, err := openListener(port, listenFd)
	if err != nil {
		emitLog(s.socksListenFailedFmt, err)
		emitStatus(statusFatal, "socks listen failed")
		log.Fatalf("listen 127.0.0.1:%d: %v", port, err)
	}
	actualPort := ln.Addr().(*net.TCPAddr).Port

	if err := writeReady(profileDir, actualPort); err != nil {
		emitLog(s.writeReadyFailedFmt, err)
		emitStatus(statusFatal, "write ready marker failed")
		log.Fatalf("write ready marker: %v", err)
	}
	emitProgress(s.socksUpFmt, actualPort)
	emitStatus(statusOK, "")
	log.Printf("openflux helper: SOCKS5 on 127.0.0.1:%d transport=%s", actualPort, link.Transport)

	// Handover (§2.8): host sends an event instead of killing the helper; the transport reconnects on its own.
	setHostEventHandler(func(event string) {
		switch event {
		case "handover", "netlost", "netback", "stall":
			emitLog(s.handoverLog)
			hoTransport.Handover()
		}
	})

	// Accept-петля — канон shared/socks5.
	serveSocksListener(ln, func(c net.Conn) {
		handleConn(c, user, pass, tun, resolver, dialTimeout)
	})
	return 0
}

// settingDuration reads a setting in seconds (MODULE_API §2.11), falling back to defSec if unparseable.
func settingDuration(cfg map[string]string, key string, defSec int) time.Duration {
	if v, err := strconv.Atoi(strings.TrimSpace(cfg[key])); err == nil && v > 0 {
		return time.Duration(v) * time.Second
	}
	return time.Duration(defSec) * time.Second
}

// waitTransportUp polls IsConnected() (transport.Transport has no readiness channel) up to just under the host's READY_TIMEOUT.
func waitTransportUp(t transport.Transport) bool {
	deadline := time.Now().Add(readyWaitBudget)
	for time.Now().Before(deadline) {
		if t.IsConnected() {
			return true
		}
		time.Sleep(transportUpPoll)
	}
	return t.IsConnected()
}

// handleConn is the module's CONNECT path; the SOCKS5 protocol itself lives in shared/socks5.
func handleConn(c net.Conn, user, pass string, tun *tunnel.TCPTunnel, resolver *protectedResolver, dialTimeout time.Duration) {
	defer c.Close()
	br := bufio.NewReader(c)

	req, ok := socksHandshake(c, br, user, pass)
	if !ok {
		return
	}
	if req.Cmd == socksCmdUDPAssociate {
		// UDP ASSOCIATE is deliberately unsupported: the tunnel's gVisor stack only registers tcp.NewProtocol.
		_, _ = c.Write(socksRep(0x07))
		return
	}

	host := req.TargetLabel()
	target := net.JoinHostPort(host, strconv.Itoa(int(req.Port)))
	dialStart := time.Now()

	ip, rerr := resolveV4(req, resolver)
	if rerr != nil {
		log.Printf("[SOCKS] resolve FAILED host=%s err=%v", host, rerr)
		// 0x04 host unreachable, not 0x01: the tunnel just can't route this address family.
		_, _ = c.Write(socksRep(0x04))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	up, err := tun.DialTCP(ctx, net.JoinHostPort(ip, strconv.Itoa(int(req.Port))))
	cancel()
	if err != nil {
		log.Printf("[SOCKS] tunnel dial FAILED target=%s ip=%s elapsed=%v err=%v", target, ip, time.Since(dialStart), err)
		_, _ = c.Write(socksRep(0x01))
		return
	}
	defer up.Close()
	if _, err := c.Write(socksRep(0x00)); err != nil {
		return
	}
	relayBidi(c, br, up, target, dialStart)
}

// resolveV4 picks IPv4 in one place for both literal and domain targets, since the tunnel is IPv4-only.
func resolveV4(req socksRequest, resolver *protectedResolver) (string, error) {
	if req.IsIP() {
		if !req.IP.Is4() && !req.IP.Is4In6() {
			return "", fmt.Errorf("IPv6 target %v: tunnel is IPv4-only", req.IP)
		}
		return req.IP.Unmap().String(), nil
	}
	ips, err := resolver.LookupHost(req.Host)
	if err != nil {
		return "", err
	}
	for _, s := range ips {
		if a := net.ParseIP(s); a != nil && a.To4() != nil {
			return a.To4().String(), nil
		}
	}
	return "", fmt.Errorf("no IPv%d address for %s (got %v)", dnsQueryFamilyV4, req.Host, ips)
}

// handoverer is a local interface (not a transport.Transport method, which must stay an exact upstream copy).
type handoverer interface{ Handover() }

// hostDNSServers feeds transport.SetBootstrapDNSServers so the transport resolves its own hosts via the host's physical DNS.
func hostDNSServers(csv string) []string {
	var out []string
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
