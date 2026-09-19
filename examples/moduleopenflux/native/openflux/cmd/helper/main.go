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
	"sync/atomic"
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
	// По строке на ПРИЧИНУ события хоста (MODULE_API §2.8). Раздельно, а не один текст с
	// подстановкой: юзер читает их в общем логе, и «сменилась сеть» на месте «проба не прошла»
	// — не стилистика, а неверный факт (ровно это и печаталось, пока причина была одна).
	handoverLog             string
	netLostLog              string
	netBackLog              string
	stallLog                string
	dnsUpdatedFmt           string // %d — сколько резолверов прислал хост
}

var ofStringsRU = ofStrings{
	badLinkFmt:              "OpenFlux: неверная ссылка: %v",
	openingTransportFmt:     "OpenFlux: открываю транспорт %s",
	transportStartFailedFmt: "OpenFlux: транспорт не стартовал: %v",
	transportNotUpFmt:       "OpenFlux: транспорт не поднялся за %s — выходим, чтобы хост перезапустил",
	socksListenFailedFmt:    "OpenFlux: не удалось взять SOCKS-листенер: %v",
	writeReadyFailedFmt:     "OpenFlux: не удалось записать маркер готовности: %v — выходим, чтобы хост перезапустил",
	socksUpFmt:              "OpenFlux: SOCKS5 поднят на 127.0.0.1:%d",
	handoverLog:             "хендовер: сменилась сеть — переустанавливаю транспорт, туннель не пересобираем",
	netLostLog:              "сети нет — жду её возвращения, попытки подъёма приостановлены",
	netBackLog:              "сеть вернулась — переустанавливаю транспорт немедленно",
	stallLog:                "хост не дождался ответа через туннель — передозваниваюсь (сеть не менялась)",
	dnsUpdatedFmt:           "сеть сменилась — беру её DNS (%d шт.) вместо прежних",
}

var ofStringsEN = ofStrings{
	badLinkFmt:              "OpenFlux: bad link: %v",
	openingTransportFmt:     "OpenFlux: opening %s transport",
	transportStartFailedFmt: "OpenFlux: transport start failed: %v",
	transportNotUpFmt:       "OpenFlux: transport did not come up within %s - exiting so the host can restart",
	socksListenFailedFmt:    "OpenFlux: SOCKS listener failed: %v",
	writeReadyFailedFmt:     "OpenFlux: failed to mark readiness: %v - exiting so the host can restart",
	socksUpFmt:              "OpenFlux: SOCKS5 up on 127.0.0.1:%d",
	handoverLog:             "handover: network changed, re-establishing the transport (tunnel is kept)",
	netLostLog:              "no network - waiting for it to come back, start-up attempts paused",
	netBackLog:              "network is back - re-establishing the transport right away",
	stallLog:                "the host saw no answer through the tunnel - re-dialing (network unchanged)",
	dnsUpdatedFmt:           "network changed - switching to its DNS servers (%d)",
}

// ofStringsFor — APP_LANG "ru" → русский стол, всё остальное (в т.ч. пусто/неизвестно) → английский.
// Правило выбора — канонное (`stringsForLang`, shared/hostproto): трактовка `APP_LANG`
// принадлежит хосту, а модулю — только СОДЕРЖИМОЕ таблиц.
func ofStringsFor(lang string) ofStrings {
	return stringsForLang(lang, ofStringsRU, ofStringsEN)
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

// decodeImportLink parses openflux-server's deep-link payload
// (openflux://import?data=<base64url-no-pad JSON>, see this file's header
// comment for the exact JSON shape and https://github.com/wlruscfd/openflux-server's
// controlplane/internal/api/deeplink.go for where it's generated). Returns
// the transport name and, for yandex, the doc URL directly out of the
// link - never dials control_url, for the same reason the fork's own
// Android app doesn't: that request would go to a bare IP with none of the
// tunnel's own disguise.
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

// displayName — имя для карточки: фрагмент ссылки, иначе — осмысленный дефолт по транспорту.
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

	// Разбор булевой настройки — канонный (`parseBoolSetting`, shared/hostproto): сравнение с
	// одним литералом здесь молча давало бы `false` на любом другом написании.
	if parseBoolSetting(cfg["SETTING_debugLog"]) {
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

	// ДОЗВОН самого транспорта (документ Яндекса / сигнальный хост MAX) — глобально, package-level
	// (transport/protect.go, дословная копия openflux-server): вендорный код внутри yandex.go/oneme
	// не принимает dial параметром конструктора, а зовёт transport.ProtectedDialer() сам.
	// protectFdFunc — канон shared/protect. РЕЗОЛВ через этот глобал больше не идёт: им занят
	// канон (ниже), которому protect приходит явным параметром.
	transport.SetProtector(func(fd int) bool { return protectFdFunc(protectPath)(int32(fd)) })
	// Bootstrap-резолверу транспорта отдаются ФИЗИЧЕСКИЕ DNS хоста: свои хосты (docs.yandex.ru
	// и т.п.) он иначе резолвил бы через захардкоженные публичные серверы transport/protect.go,
	// недостижимые в сетях, где провайдер отдаёт только свой резолвер.
	//
	// ⛔ Список серверов разбирает ОДИН парсер — канонный (`newProtectedResolver` выше), и
	// владеет им резолвер. Bootstrap получает ЕГО снимок, а не второй разбор той же строки:
	// две грамматики одного формата успели разойтись (свой разбор не приводил голый IP к
	// `ip:53`), и ровно так же разъезжались бы дальше на каждой правке. Та же форма — в
	// обработчике `dns=` ниже: один writer, один снимок обоим потребителям.
	transport.SetBootstrapDNSServers(resolver.currentServers())
	// Резолвер для ВСЕГО остального кода модуля (вендорный `yandex.go`/`oneme` резолвит через
	// `net.DefaultResolver`) — канонная прокладка shared/dns, а не своя копия в transport/.
	// Провайдером идёт `transport.BootstrapDNSServers`: список остаётся ЖИВЫМ, поэтому `dns=`
	// доезжает и сюда, не пересоздавая резолвер.
	//
	// Что сведение поменяло против прежней `transport.ProtectedResolver()`: protect берётся явным
	// параметром (`protectPath`), а не через package-level `protectFD` — форма, которую контракт
	// требует предпочитать (MODULE_API §4, там же разобран случай, когда такой глобал остался
	// незаполненным и давал SIGSEGV); появился повтор по TCP, если UDP до резолвера не доходит;
	// бюджет дозвона стал канонным `dnsQueryTimeout` вместо 30с общего диалерного — тридцать
	// секунд на КАЖДЫЙ недостижимый резолвер и есть та пауза, которой оборачивалась смена сети.
	net.DefaultResolver = protectedNetResolver(transport.BootstrapDNSServers, protectPath)

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

	// Хендовер: дескриптор объявляет `handoverMode: "signal"` + `hostEvents` (все четыре причины,
	// §2.8) — хост НЕ убивает helper на смене сети, а шлёт событие в живой процесс. Реакция —
	// `Handover()`, который с синхронизации форка делегирует в ForceReconnect: рвёт живую сессию
	// ИЛИ обрывает ожидание backoff между попытками (то, чего старая версия не умела: "netback"
	// после реального обрыва ждал весь накопленный backoff впустую). read-петля/keepalive
	// переподключаются сами, SOCKS5-листенер и принятые соединения переживают паузу.
	//
	// Обработчик ставится ДО ожидания транспорта, а не после старта SOCKS5: пока его нет, канон
	// подтверждает событие (`EVENT_ACK` на любое) и молча выбрасывает — хост считает
	// доставленным, модуль не узнаёт ничего. А `netlost` во время ожидания подъёма — тот
	// единственный случай, ради которого причина и заведена (см. waitTransportUp/netDown).
	// Транспорт к этому моменту уже `Start()`нут, поэтому `Handover()` законен.
	setHostEventHandler(func(event string) {
		// ⛔ DNS-СЕРВЕРА ОБНОВЛЯЮТСЯ ОТДЕЛЬНЫМ СОБЫТИЕМ, А НЕ ВНУТРИ handover'а.
		//
		// `DNS_SERVERS` приходит с конфигом РОВНО ОДИН раз — при запуске процесса, и описывает
		// сеть, активную в тот момент. После смены сети прежние резолверы недостижимы: запрос
		// уходит и не возвращается, SOCKS5 CONNECT отвечает `0x04 host unreachable`, а транспорт
		// при этом ЖИВ — поэтому ни `handover`, ни `ForceReconnect` этого не лечат. Замер на
		// устройстве 2026-09-17: процесс прожил ~12 часов через несколько смен сети, все резолвы
		// били в DNS первой сети (`dns: read 8.8.4.4:53 … i/o timeout`), связь возвращал только
		// ручной перезапуск модуля — он же и переподставлял `DNS_SERVERS`.
		//
		// Событие приходит ПЕРЕД `handover`/`netback`, чтобы переподключение транспорта уже
		// резолвило свой хост актуальными серверами. Применяется к ОБОИМ потребителям списка:
		// резолверу SOCKS5-таргетов и bootstrap-резолверу самого транспорта — оба питались одним
		// и тем же `DNS_SERVERS`, и обновить один из них значило бы оставить вторую половину
		// отказа на месте.
		//
		// ⛔ Применённый список берётся У РЕЗОЛВЕРА, а не разбирается повторно из события.
		// `SetServers` отвергает вход, из которого не вышло ни одного сервера (оставляет
		// прежний), а `SetBootstrapDNSServers` на пустом списке ВОЗВРАЩАЕТ ДЕФОЛТНЫЕ публичные
		// резолверы — на мусорном `dns=` два потребителя разъехались бы: SOCKS5 остался бы на
		// рабочих серверах, транспорт ушёл бы на публичные. Снимок делается ОДИН и идёт и в
		// bootstrap, и в лог, поэтому число в логе — фактически применённое, а не присланное.
		//
		// Сам резолвер SOCKS5-таргетов обновляет КАНОН (`newProtectedResolver` подписан на список
		// хоста), и к этой строке `currentServers` уже актуален. Здесь остаётся ВТОРОЙ потребитель
		// того же списка — bootstrap транспорта, про который канон не знает и знать не может: он
		// живёт в вендорном `transport/`.
		if _, ok := parseDNSEvent(event); ok {
			applied := resolver.currentServers()
			transport.SetBootstrapDNSServers(applied)
			emitLog(s.dnsUpdatedFmt, len(applied))
			return
		}
		switch event {
		case "handover":
			// Сеть РЕАЛЬНО сменилась: старые сокеты привязаны к ушедшей сети, их надо бросить.
			emitLog(s.handoverLog)
			netDown.Store(false)
			hoTransport.Handover()
		case "netback":
			// Сеть вернулась — пробуем НЕМЕДЛЕННО, не досиживая свой backoff (ForceReconnect
			// обрывает и ожидание, если сессии сейчас нет).
			emitLog(s.netBackLog)
			netDown.Store(false)
			hoTransport.Handover()
		case "netlost":
			// Сети нет. Рвать соединение незачем (его уже нет), а вот жечь бюджет подъёма и
			// умирать «транспорт не поднялся» — вредно: рестарт упрётся в то же самое.
			emitLog(s.netLostLog)
			netDown.Store(true)
		case "stall":
			// Проба хоста не прошла, но сеть НЕ менялась: передозваниваемся, ничего не заявляя
			// про смену сети (прежде на этот повод приходил `handover`, и модуль печатал юзеру
			// «сменилась сеть» — неправду).
			emitLog(s.stallLog)
			hoTransport.Handover()
		}
	})

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
//
// netDown — «хост сказал: годной сети нет» (событие `netlost`, снимается `netback`; MODULE_API
// §2.8). Флаг, а не канал: читателю нужно текущее состояние, а не история переходов.
var netDown atomic.Bool

func waitTransportUp(t transport.Transport) bool {
	deadline := time.Now().Add(readyWaitBudget)
	for time.Now().Before(deadline) {
		if t.IsConnected() {
			return true
		}
		time.Sleep(transportUpPoll)
		// ⛔ Время БЕЗ СЕТИ в бюджет не идёт. «Транспорт не поднялся за 1m30s» — утверждение о
		// транспорте, и выход ради рестарта хостом чинит ровно те случаи, где виноват транспорт.
		// Пока сети нет, рестарт не меняет НИЧЕГО: новый процесс упрётся в то же самое и умрёт
		// через те же 90 с — цикл перезапусков на всё время обрыва вместо тихого ожидания.
		// ⚠ Флаг ставит ТОЛЬКО хост (`netlost`): «сеть есть, но транспорт не отвечает» — это
		// по-прежнему вина транспорта, и бюджет там обязан тикать.
		//
		// ⛔ ПОЛЯРНОСТЬ. Дедлайн отодвигается, когда сети НЕТ, — только так «время без сети не
		// идёт в бюджет». Обратное условие (`!netDown`) отодвигало его при ЖИВОЙ сети, то есть
		// ровно на тот же шаг, на который продвигались часы: `time.Now()` и `deadline` росли
		// синхронно, и цикл не завершался НИКОГДА — вместо честной сдачи за readyWaitBudget
		// модуль ждал молча, пока его не снимет хост по своему READY_TIMEOUT. Вторая половина
		// той же перевёрнутости: при пропавшей сети бюджет, наоборот, истекал ровно по часам —
		// то есть модуль сдавался именно тогда, когда рестарт заведомо ничего не чинит.
		if netDown.Load() {
			deadline = deadline.Add(transportUpPoll)
		}
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

// parseDNSEvent — разбор события хоста `dns=<ip[,ip...]>` (MODULE_API §2.8). `true` — событие
// ИМЕННО это; на любом другом возвращает `false`, и вызывающий идёт своим `switch`.
//
// Префиксная форма с полезной нагрузкой, а не голое имя причины: список обязан приехать ВМЕСТЕ с
// событием. Хост узнаёт новые резолверы ровно в момент смены сети, а обратного канала «спроси у
// хоста» у модуля нет — голое имя заставило бы его гадать, откуда взять адреса.
//
// Разбор — КАНОННЫЙ `normalizeDNSServers` (shared/dns), тот же, которым `newProtectedResolver`
// читает `DNS_SERVERS` из конфига: формат один, и вторая его копия разошлась бы с первой ровно
// там, где список приходит по второму пути. Своя копия здесь уже была и уже разошлась — не
// приводила голый IP к `ip:53`.
//
// Пустой список (`dns=`) НЕ считается событием: стирать рабочие резолверы по сообщению, в котором
// ничего нет, — худший исход, чем проигнорировать его.
func parseDNSEvent(event string) ([]string, bool) {
	const prefix = "dns="
	if !strings.HasPrefix(event, prefix) {
		return nil, false
	}
	list := normalizeDNSCsv(strings.TrimPrefix(event, prefix))
	if len(list) == 0 {
		return nil, false
	}
	return list, true
}
