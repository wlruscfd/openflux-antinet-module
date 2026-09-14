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
// приложению). Пусто (старый хост / деградация) → фоллбэк на обычный net.DefaultResolver.LookupHost.
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
	dnsQueryTimeout  = 3 * time.Second
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
// вход → резолвер с пустым server-списком, LookupHost сам фоллбэкнет на net.DefaultResolver.
func newProtectedResolver(dnsServersCsv, protectPath string) *protectedResolver {
	var servers []string
	for _, s := range strings.Split(dnsServersCsv, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if net.ParseIP(s) != nil {
			s = net.JoinHostPort(s, "53")
		}
		servers = append(servers, s)
	}
	return &protectedResolver{
		servers:     servers,
		protectPath: protectPath,
		cache:       map[string]dnsCacheEntry{},
		inFlight:    map[string]chan struct{}{},
	}
}

// LookupHost — сигнатура зафиксирована shared/socks5's parseSocksUDP (интерфейс
// `interface{ LookupHost(string) ([]string, error) }`), используется И этим интерфейсом (UDP
// ASSOCIATE target-резолв), И напрямую TCP CONNECT-путём (handleConn).
func (r *protectedResolver) LookupHost(host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}
	if r == nil || len(r.servers) == 0 {
		// ⛔ Контекст обязателен: `net` строит из него дедлайн, а `context.WithDeadline` на
		// nil-родителе ПАНИКУЕТ и убивает процесс хелпера. Бюджет — тот же `dnsQueryTimeout`,
		// что и у собственного пути: неограниченного ожидания здесь быть не должно.
		ctx, cancel := context.WithTimeout(context.Background(), dnsQueryTimeout)
		defer cancel()
		return net.DefaultResolver.LookupHost(ctx, host)
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
	for _, qtype := range [...]dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		for _, srv := range r.servers {
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
