// SPDX-License-Identifier: GPL-3.0-or-later
//
// OpenFlux — helper протокол-модуля AntiNet. ВЕСЬ модульный код — в этом одном файле: точки входа
// (C-ABI на Android, argv на десктопе), протокол разговора с хостом, SOCKS5, protect/off-TUN,
// резолвер и маркер готовности дают КАНОНЫ `shared/*`, которые build.py инжектит перед сборкой.
//
// Модуль обязан определить РОВНО ДВЕ функции, и они обе ниже:
//
//	realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int
//	moduleCall(verb, arg string) string
//
// Data-plane — порт клиентской половины https://github.com/p1neappleXpress/OpenFlux (GPL-3.0):
// SOCKS5 → netstack → сырые IPv4-пакеты → транспорт (Yandex Docs / MAX) → exit-node.
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

// ── Ссылка ────────────────────────────────────────────────────────────────────────────────────
//
// Грамматика (апстрим, https://github.com/p1neappleXpress/OpenFlux):
//
//	openflux://yandex?url=<urlencoded адрес документа Яндекс.Документов>[#Имя]
//	openflux://oneme?token=<токен MAX>&uid=<id собеседника>[#Имя]
//
// Схема ОДНА (`openflux`), а транспорт — первый сегмент. Так сделано намеренно: `yandex://` и
// `oneme://` — слишком общие имена, чтобы занимать их в реестре схем хоста, а различать транспорты
// внутри своей схемы модулю ничего не стоит.
//
// У апстрима формата ссылки нет вовсе — он конфигурируется флагами CLI (`-transport`, `-url`,
// `-maxToken`, `-maxUid`), поэтому имена параметров взяты оттуда один в один.
//
// Плюс форма нашего форка (openflux-server, https://github.com/wlruscfd/openflux-server) — ссылка,
// которую выдаёт controlplane/админ-панель на созданный ключ (см. её buildDeepLink):
//
//	openflux://import?data=<base64url-JSON без паддинга>
//	JSON = {"name","mode":"key","control_url","key_token","doc_url","transport"}
//
// doc_url/transport лежат в самой ссылке (как и Android-приложение форка, этот модуль НЕ ходит на
// control_url за ними: такой запрос шёл бы на голый IP без маскировки транспорта, и сеть, уже
// блокирующая прямой доступ к нему, заблокирует и его). control_url/key_token принимаются, но не
// используются — у модуля нет своей проверки квоты ключа. Публикуется параллельно апстримной форме
// и не заменяет её: они разбираются одним декодером (parseOpenFluxLink), различаясь только первым
// сегментом (`import` вместо имени транспорта).
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

// ── Локализация текста для юзера (MODULE_API §2.9) ────────────────────────────────────────────
//
// Граница проходит по ПРИЁМНИКУ, а не по маркеру: текст ПОСЛЕ тега в `PROGRESS|`/`LOG|` юзер видит
// тостом и на экране «Логи», значит он обязан быть на языке AntiNet (`APP_LANG` из конфига). Сами
// теги, таймстамп-префикс, `detail` у `STATUS|` и весь `log.Printf` остаются ASCII/английскими:
// первые разбирает хост, вторые читает разработчик грепом.
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

// openFluxLink — разобранная ссылка. Поля повторяют флаги апстрима, чтобы сверка «что приехало»
// сводилась к чтению одной структуры.
type openFluxLink struct {
	Transport string // yandex | oneme
	URL       string // yandex: адрес документа
	Token     string // oneme: токен MAX
	UID       int64  // oneme: id собеседника (exit-node)
	Name      string // фрагмент ссылки — имя для карточки конфига
}

// parseOpenFluxLink — ЕДИНЫЙ декодер ссылки: его зовут и коннект-путь, и `summarize`, и
// `normalize`. Второго парсера у модуля быть не должно — разойдутся на первой же правке
// грамматики, и карточка начнёт показывать не тот сервер, к которому идёт подключение.
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

	// openflux-server's own deep-link shape - see decodeImportLink's doc
	// comment. Unwraps to the same {Transport, URL, Name} shape the plain
	// yandex/oneme forms below produce, so everything past this point
	// (server(), displayName(), the connect path) treats it identically.
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

// decodeImportLink parses openflux-server's deep-link payload (header comment
// above has the JSON shape). Never dials control_url — same reason the fork's
// own Android app doesn't: that request would hit a bare IP with none of the
// tunnel's disguise.
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

// server — что показать в карточке конфига как «сервер». Для yandex это хост документа, для
// oneme — сигнальный хост MAX плюс id собеседника: два конфига одного транспорта обязаны
// РАЗЛИЧАТЬСЯ в списке, иначе карточка врёт.
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

// normalizeOpenFlux — НЕ-link формы (JSON / base64-JSON) → канонический openflux://-link
// (MODULE_API §2.6). Уже link / чужой формат → "". Ключи JSON — те же, что параметры ссылки.
func normalizeOpenFlux(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(strings.ToLower(s), linkScheme+"://") {
		return ""
	}
	if !strings.HasPrefix(s, "{") {
		return "" // base64-обёртку не принимаем: у формата нет собственного признака, и любой
		// base64-текст соседнего модуля мы бы «узнали» как свой.
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

// moduleCall — parse-only сабкоманды (MODULE_API §2.2). Канон `shared/entry` зовёт её из argv на
// десктопе и из `antinet_module_call` в Android-слоте — тело одно.
// `canping` не объявлен: `pingNeedsConsent` в дескрипторе нет, интерактива у модуля тоже, и хост
// эту сабкоманду не спрашивает.
func moduleCall(verb, arg string) string {
	switch verb {
	case "summarize":
		l, err := parseOpenFluxLink(arg)
		if err != nil {
			return "\n" // чужая схема/битая ссылка — две пустые строки, хост оставит плейсхолдер
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

	// Канал событий хоста — САМЫМ ПЕРВЫМ (десктоп: построчный stdin; Android-слот: no-op, там хост
	// зовёт antinet_module_event напрямую). Канон shared/lifecycle.
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
		// Причина неподъёма обязана уйти хосту ЯВНО (`LOG|` виден юзеру, `STATUS|` — вход решения
		// хоста), иначе наружу пойдёт только «модуль не запустился».
		emitLog(s.badLinkFmt, err)
		emitStatus(statusFatal, "bad link")
		log.Fatalf("parse LINK: %v", err)
	}

	dialTimeout := settingDuration(cfg, "SETTING_dialTimeoutSec", defaultDialSec)
	keepAlive := settingDuration(cfg, "SETTING_keepAliveSec", defaultKeepSec)

	// Резолвер SOCKS5 CONNECT-таргетов — канон shared/dns: protected off-tunnel, TTL-кэш,
	// single-flight. Домены, приходящие в SOCKS5 CONNECT, резолвятся ИМ: туннель OpenFlux несёт
	// ТОЛЬКО TCP (см. ниже), резолвить внутри него нечего.
	resolver := newProtectedResolver(cfg["DNS_SERVERS"], protectPath)

	// Дозвон и резолв САМОГО транспорта (документ Яндекса / сигнальный хост MAX) — глобально,
	// package-level (transport/protect.go, дословная копия openflux-server): вендорный код внутри
	// yandex.go/oneme больше не принимает dial параметром конструктора, а зовёт
	// transport.ProtectedDialer()/ProtectedResolver() сам. protectFdFunc — канон shared/protect.
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

	// Ждём, пока транспорт реально встанет, и ТОЛЬКО потом отмечаем готовность: маркер `ready`
	// означает «через меня можно ходить», а не «процесс жив». Отметить раньше — значит отдать
	// хосту зелёный свет на сессию, которой ещё нет, и получить обрывы вместо честного ожидания
	// (хост готов ждать до своего READY_TIMEOUT ~95с, см. §2.10).
	if !waitTransportUp(trans) {
		// Чистый выход, а не зомби (§2.3 п.7): хост поднимет нас заново своим death-watchdog'ом
		// сразу, тогда как висящий без маркера процесс он будет ждать до конца бюджета впустую.
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

	// Хендовер: дескриптор объявляет `handoverMode: "signal"` + `hostEvents` (все четыре причины,
	// §2.8) — хост НЕ убивает helper на смене сети, а шлёт событие в живой процесс. Реакция —
	// оборвать живую сессию транспорта и ничего больше: read-петля/keepalive транспорта уже умеют
	// переподключаться сами (yandex.(*YandexDocsTransport).Handover / oneme.(*OneMeTransport).Handover),
	// а SOCKS5-листенер и уже принятые соединения переживают паузу вместо полного перезапуска модуля.
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

// settingDuration — значение настройки в секундах (MODULE_API §2.11). Непарсящееся/нулевое →
// дефолт: хост ВСЕГДА шлёт значение, но модуль обязан пережить и пустое.
func settingDuration(cfg map[string]string, key string, defSec int) time.Duration {
	if v, err := strconv.Atoi(strings.TrimSpace(cfg[key])); err == nil && v > 0 {
		return time.Duration(v) * time.Second
	}
	return time.Duration(defSec) * time.Second
}

// waitTransportUp — ограниченное ожидание готовности транспорта. Потолок — ЧУТЬ МЕНЬШЕ хостового
// READY_TIMEOUT (~95с): дождаться собственного дедлайна и выйти чисто лучше, чем быть убитым
// снаружи, потому что чистый выход хост лечит немедленным перезапуском.
//
// ⚠ Опрос, а не событие: у апстримного интерфейса `transport.Transport` нет канала готовности,
// только `IsConnected()`. Заводить свой означало бы править апстримную абстракцию ради того, что
// опрос раз в 200 мс решает без последствий.
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

// handleConn — CONNECT-путь модуля. Сам протокол SOCKS5 (приветствие, user/pass, разбор запроса,
// реле) — канон shared/socks5; модулю принадлежит только ТРАНСПОРТ: дозвон через свой туннель.
func handleConn(c net.Conn, user, pass string, tun *tunnel.TCPTunnel, resolver *protectedResolver, dialTimeout time.Duration) {
	defer c.Close()
	br := bufio.NewReader(c)

	req, ok := socksHandshake(c, br, user, pass)
	if !ok {
		return
	}
	if req.Cmd == socksCmdUDPAssociate {
		// UDP ASSOCIATE не поддерживаем ОСОЗНАННО, а не по недоделке: gVisor-стек туннеля
		// регистрирует один только `tcp.NewProtocol`, а exit-node отдаёт пакеты в raw-socket TCP —
		// произвольный UDP по этому транспорту не проходит физически. Честный `0x07` лучше, чем
		// принятая ассоциация, из которой ничего не уходит: UDP-каскад за таким модулем не
		// поднимется в любом случае, и различаться должны причина и диагноз (§2.3 п.6).
		_, _ = c.Write(socksRep(0x07))
		return
	}

	host := req.TargetLabel()
	target := net.JoinHostPort(host, strconv.Itoa(int(req.Port)))
	dialStart := time.Now()

	ip, rerr := resolveV4(req, resolver)
	if rerr != nil {
		log.Printf("[SOCKS] resolve FAILED host=%s err=%v", host, rerr)
		// 0x04 host unreachable, а не 0x01: адресат назван корректно, но этой семьёй адресов
		// туннель не ходит — это «до него отсюда нет пути», а не «что-то пошло не так».
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

// resolveV4 — адресат как ЛИТЕРАЛЬНЫЙ IPv4. Туннель OpenFlux несёт только IPv4 (клиентский
// netstack поднят на 10.10.10.2/24 с одним `ipv4.NewProtocol`), поэтому отбор семьи — здесь, в
// одной точке, а не отдельно у литерала и отдельно у домена.
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

// handoverer — реакция на событие хоста (§2.8), реализована и yandex.YandexDocsTransport, и
// oneme.OneMeTransport. Отдельный локальный интерфейс, а не метод на `transport.Transport`: тот
// живёт в transport.go, который обязан оставаться дословной копией openflux-server (см. этого
// файла шапку и examples/moduleopenflux/README.md) — добавлять в него что-то модульное нельзя.
type handoverer interface{ Handover() }

// hostDNSServers — DNS_SERVERS (те же bare-IP/ip:port через запятую, что читает shared/dns) для
// transport.SetBootstrapDNSServers: транспорт резолвит СВОИ хосты (docs.yandex.ru и т.п.) через
// физические DNS хоста, а не через захардкоженные публичные резолверы transport/protect.go.
func hostDNSServers(csv string) []string {
	var out []string
	for _, s := range strings.Split(csv, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
