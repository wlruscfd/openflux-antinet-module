// SPDX-License-Identifier: MIT

package main

// shared/dns is off-tunnel, protected, TTL-cached A/AAAA resolution for the module's own dial targets, injected by build.py.

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

// newProtectedResolver parses DNS_SERVERS; an empty/invalid input yields an empty server list, and LookupHost falls back.
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

// LookupHost's signature is fixed by shared/socks5's parseSocksUDP interface; also used directly by the TCP CONNECT path.
func (r *protectedResolver) LookupHost(host string) ([]string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}
	if r == nil || len(r.servers) == 0 {
		// A context is required: context.WithDeadline on a nil parent panics and kills the helper process.
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
		// This host is already being resolved on another goroutine - wait for its result instead of duplicating the query.
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

// queryAll tries each configured server in turn for A, then AAAA if none had an A record; first success wins.
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

// queryOneServer dials through dialControl - the same protect primitive as the TCP CONNECT socket - or the resolve leaks into the TUN.
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
