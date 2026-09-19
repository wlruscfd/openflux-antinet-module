// SPDX-License-Identifier: MIT

package main

// КАНОН shared/dns — off-tunnel, protected, TTL-cached A/AAAA резолв СОБСТВЕННЫХ
// dial-таргетов модуля (TCP CONNECT host + SOCKS5 UDP ASSOCIATE domain-таргеты, RFC 1928 §7).
// Инжектируется build.py в main-пакет helper'а при `"dnsResolver": true`, как shared/offtun и
// shared/socks5.
//
// ⛔ Копию этого файла в своём модуле не заводи (MODULE_API §4). Он инжектируется в КАЖДЫЙ модуль с
// флагом, и вторая реализация рядом неизбежно с ним разойдётся — не в сборке, а в рантайме.
//
// Почему это вообще отдельный резолвер, а не net.DefaultResolver: он нужен модулю, чья dial-цель —
// РЕАЛЬНЫЙ адрес в интернете, вне собственного туннеля. Такой резолв обязан явно избегать
// TUN-перехвата тем же способом, что уже защищает CONNECT-сокет (dialControl/SCM_RIGHTS) — иначе
// резолв-сокет уходит в TUN, перехватывается DNS-hijack правилом и крутится через ЧУЖОЙ
// (sing-box'овый dns-remote/direct/local) пайплайн: не сломано, но непредсказуемо медленно и
// зависит от состояния каскада. Модулю, который резолвит ВНУТРИ уже поднятого туннеля (qWDTT — через
// свой netstack), этот канон не нужен и флаг ему объявлять незачем.
//
// От модуля канон требует РОВНО ОДНО: функцию `dialControl(protectPath string, st *protectStat)
// func(network, address string, c syscall.RawConn) error` — тот же protect-адаптер, что модуль и так
// держит в своём `platform_android.go`/`platform_other.go` (MODULE_API §4).
//
// TTL-кэш + single-flight: без кэша КАЖДОЕ соединение к одному и тому же хосту (типично — сервер
// каскада) платит полный резолв заново; без single-flight параллельные соединения к тому же хосту
// дублируют сетевой запрос (thundering herd). Тот же класс защиты, что qWDTT'шный
// dnsCacheEntry/resolveHostCached, у которого резолв без кэша стоил 5.1-5.4с всплесков.
//
// DNS-сервера — С ХОСТА, НЕ хардкод (категорический запрет проекта на публичные резолверы в коде):
// `DNS_SERVERS=<ip[,ip...]>` — generic KEY=VALUE-ключ конфига, тот же choke point, где хост уже
// строит LISTEN_PORT/SOCKS_USER/SOCKS_PASS/LINK. Хост населяет его РЕАЛЬНЫМИ физическими DNS
// адаптера (то же семейство, что ProtectedSocketSupport.kt/physicaladapter.pas уже даёт остальному
// приложению). Пусто (старый хост / деградация) → фоллбэк на резолверы САМОЙ ОС через прокладку
// `systemResolver` (`dns_netresolver.go`): список берётся у системы, но запрос всё равно уходит
// защищённым сокетом. `net.DefaultResolver` в этой роли запрещён — почему, там же.
//
// Файл БЕЗ build-тега: платформенного здесь ничего нет, вся развилка сидит в `dialControl` модуля.

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	dnsCacheTTL      = 60 * time.Second
	dnsMaxPacketSize = 1500
)

type dnsCacheEntry struct {
	ips     []string
	expires time.Time
}

type protectedResolver struct {
	servers     []string // "ip:port"
	protectPath string

	mu       sync.Mutex
	cache    map[string]dnsCacheEntry
	inFlight map[string]chan struct{}
}

// newProtectedResolver — parses DNS_SERVERS (bare IPs or ip:port, comma-separated). Пустой/невалидный
// вход → резолвер с пустым server-списком, и `LookupHost` уходит на прокладку к резолверам ОС
// (`systemResolver`), а не на `net.DefaultResolver`.
func newProtectedResolver(dnsServersCsv, protectPath string) *protectedResolver {
	r := &protectedResolver{
		servers:     normalizeDNSCsv(dnsServersCsv),
		protectPath: protectPath,
		cache:       map[string]dnsCacheEntry{},
		inFlight:    map[string]chan struct{}{},
	}
	// ⛔ АКТУАЛИЗАЦИЯ — АВТОМАТИЧЕСКАЯ, не обязанность модуля. Каждый новый список от хоста
	// (событие `dns=`) сам доедет сюда и сбросит кэш: записи в нём получены через ПРЕЖНЮЮ сеть.
	// Пока это писал автор модуля, оно выглядело как пять строк в обработчике событий — и ровно
	// так же молча отсутствовало у того, кто про них не прочитал.
	//
	// Модулю остаётся ОДНО: объявить `"dns"` в `hostEvents` дескриптора, иначе хост событие просто
	// не пришлёт. Это объявление, а не код, и его отсутствие видно в дескрипторе.
	onHostDNSServers(r.SetServers)
	return r
}

// SetServers заменяет список резолверов на актуальный и сбрасывает кэш.
//
// ⛔ ЗАЧЕМ. Список приходит от хоста РОВНО ОДИН раз — с конфигом при запуске процесса
// (`DNS_SERVERS`), и описывает сеть, активную В ТОТ момент. После смены сети (Wi-Fi → LTE, другая
// точка) прежние резолверы в новой сети недостижимы: запрос уходит и не возвращается, `LookupHost`
// отдаёт таймаут чтения, а SOCKS5 CONNECT — `0x04 host unreachable`. Транспорт модуля при этом
// ЖИВ, поэтому ни его переподключение, ни `ForceReconnect` не лечат — помогает только новый
// список. Замер на устройстве 2026-09-17: процесс прожил ~12 часов через несколько смен сети, все
// резолвы били в DNS ПЕРВОЙ сети и падали по таймауту (`dns: read 8.8.4.4:53 … i/o timeout`),
// связь возвращал только ручной перезапуск модуля, который и переподставлял `DNS_SERVERS`.
//
// Кэш сбрасывается ВМЕСТЕ со списком: его записи получены через прежнюю сеть и к новой отношения
// не имеют — в частности, адреса из её split-horizon DNS.
//
// Пустой список (хост не смог определить физическую сеть) НЕ применяется: он сбросил бы
// `LookupHost` на системный фоллбэк ровно тогда, когда рабочие серверы уже есть на руках. Прежний
// список может устареть, но он заведомо получен от хоста; системный — то, что осталось, когда не
// осталось ничего (а на Android его нет вовсе).
// SetServersCsv — тот же [SetServers], но для СЫРОЙ строки хоста (`dns=<ip[,ip...]>`). Заведён,
// чтобы `strings.Split(..., ",")` не появлялся в модулях: разбор формата хоста принадлежит канону,
// и каждая его копия у потребителя — это место, где грамматика разойдётся.
func (r *protectedResolver) SetServersCsv(csv string) {
	r.SetServers(normalizeDNSCsv(csv))
}

func (r *protectedResolver) SetServers(servers []string) {
	if r == nil {
		return
	}
	normalized := normalizeDNSServers(servers)
	if len(normalized) == 0 {
		return
	}
	r.mu.Lock()
	r.servers = normalized
	r.cache = map[string]dnsCacheEntry{}
	r.mu.Unlock()
}

// currentServers — снимок списка под локом. Сам слайс НИКОГДА не правится на месте (только
// заменяется целиком в [SetServers]), поэтому читателю безопасно держать его без лока.
func (r *protectedResolver) currentServers() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.servers
}

// LookupHost — сигнатура зафиксирована shared/socks5's parseSocksUDP (интерфейс
// `interface{ LookupHost(string) ([]string, error) }`), используется И этим интерфейсом (UDP
// ASSOCIATE target-резолв), И напрямую TCP CONNECT-путём (handleConn).
func (r *protectedResolver) LookupHost(host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}
	if r == nil {
		// Резолвера нет вовсе — это не «нечем резолвить», а незаконченная инициализация модуля.
		// Отдаём ошибку, чтобы она всплыла сразу, а не превратилась в молчаливый обход.
		return nil, errNoDNSServers
	}
	if len(r.currentServers()) == 0 {
		// ⛔ НЕ `net.DefaultResolver`. Тот на Android идёт cgo-путём, мимо `net.Dialer`, то есть
		// мимо protect'а — под VPN такой запрос уходит в TUN, в туннель, который держится на
		// самом модуле: резолв ждёт транспорта, транспорт ждёт резолва. Вместо этого — прокладка
		// к резолверам САМОЙ ОС (`systemResolver`): список берётся у системы, но пакет уходит
		// нашим защищённым сокетом. Нечего взять (на Android — всегда, см. `systemDNSServers`) →
		// честная ошибка, а не обход.
		//
		// ⛔ Контекст обязателен: `net` строит из него дедлайн, а `context.WithDeadline` на
		// nil-родителе ПАНИКУЕТ и убивает процесс хелпера. Бюджет — тот же `dnsQueryTimeout`,
		// что и у собственного пути: неограниченного ожидания здесь быть не должно.
		ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
		defer cancel()
		return systemResolver(r.protectPath).LookupHost(ctx, host)
	}

	r.mu.Lock()
	if e, ok := r.cache[host]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.ips, nil
	}
	if ch, ok := r.inFlight[host]; ok {
		// Резолв ЭТОГО хоста уже идёт на другой горутине — ждём его результат вместо дублирования
		// сетевого запроса (mirror qWDTT's e.flight single-flight, тот же класс защиты).
		r.mu.Unlock()
		<-ch
		r.mu.Lock()
		e, ok := r.cache[host]
		r.mu.Unlock()
		if ok && time.Now().Before(e.expires) {
			return e.ips, nil
		}
		return nil, fmt.Errorf("dns: concurrent resolve of %s failed", host)
	}
	ch := make(chan struct{})
	r.inFlight[host] = ch
	r.mu.Unlock()

	ips, err := r.queryAll(host)

	r.mu.Lock()
	delete(r.inFlight, host)
	if err == nil {
		r.cache[host] = dnsCacheEntry{ips: ips, expires: time.Now().Add(dnsCacheTTL)}
	}
	r.mu.Unlock()
	close(ch)

	return ips, err
}

// queryAll — пробует все сконфигурированные сервера по очереди для A, затем (если ни один не дал
// A-записи) для AAAA. Первый успех побеждает — не гонка (здесь резолверы — реальные физические DNS,
// не флакающий in-tunnel путь qWDTT, гонять их параллельно незачем).
func (r *protectedResolver) queryAll(host string) ([]string, error) {
	var lastErr error
	// Снимок берётся ОДИН раз на весь обход: замена списка посреди перебора дала бы часть
	// запросов старым резолверам, часть новым, и `lastErr` уже нельзя было бы отнести ни к
	// одному из состояний.
	servers := r.currentServers()
	for _, qtype := range [...]dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		for _, srv := range servers {
			ips, err := queryOneServer(srv, r.protectPath, host, qtype, dnsQueryTimeout)
			if err == nil && len(ips) > 0 {
				return ips, nil
			}
			if err != nil {
				lastErr = err
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("dns: no records for %s", host)
	}
	return nil, lastErr
}

// queryOneServer — один UDP A/AAAA-запрос к конкретному серверу, дозвон ЧЕРЕЗ dialControl (тот же
// protect-примитив, что уже защищает TCP CONNECT-сокет) — иначе резолв-сокет уходит в TUN.
func queryOneServer(server, protectPath, host string, qtype dnsmessage.Type, timeout time.Duration) ([]string, error) {
	fqdn := host
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	name, err := dnsmessage.NewName(fqdn)
	if err != nil {
		return nil, fmt.Errorf("dns: bad name %q: %w", host, err)
	}

	var pst protectStat
	d := net.Dialer{Timeout: timeout, Control: dialControl(protectPath, &pst)}
	conn, err := d.Dial("udp", server)
	if err != nil {
		return nil, fmt.Errorf("dns: dial %s: %w", server, err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	id := uint16(time.Now().UnixNano())
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(packed); err != nil {
		return nil, fmt.Errorf("dns: write %s: %w", server, err)
	}

	buf := make([]byte, dnsMaxPacketSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("dns: read %s: %w", server, err)
	}

	var resp dnsmessage.Message
	if err := resp.Unpack(buf[:n]); err != nil {
		return nil, err
	}
	if resp.Header.ID != id {
		return nil, fmt.Errorf("dns: id mismatch from %s", server)
	}
	if resp.Header.RCode != dnsmessage.RCodeSuccess {
		return nil, fmt.Errorf("dns: rcode=%v from %s", resp.Header.RCode, server)
	}

	var ips []string
	for _, a := range resp.Answers {
		switch rr := a.Body.(type) {
		case *dnsmessage.AResource:
			ip := make(net.IP, net.IPv4len)
			copy(ip, rr.A[:])
			ips = append(ips, ip.String())
		case *dnsmessage.AAAAResource:
			ip := make(net.IP, net.IPv6len)
			copy(ip, rr.AAAA[:])
			ips = append(ips, ip.String())
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dns: no answers from %s", server)
	}
	return ips, nil
}
