// SPDX-License-Identifier: MIT

package main

// КАНОН SOCKS5 — ОДИН на все модули, инжектируется build.py в main-пакет helper'а, как
// shared/protect, shared/offtun и shared/lifecycle.
//
// ─── Что здесь лежит и почему именно это ──────────────────────────────────────────────────────
//
// Контракт модуля с хостом — SOCKS5-порт (MODULE_API §2.6), один и тот же у ВСЕХ модулей. Значит
// и протокол у них один: приветствие, user/pass (RFC 1929), разбор запроса, коды ответов,
// UDP ASSOCIATE (RFC 1928 §7), реле и политика закрытия. Разным у модулей остаётся ровно одно —
// ЧЕМ они дозваниваются до цели: qWDTT ведёт дозвон ЧЕРЕЗ свой WG-туннель (netstack), echo —
// напрямую в реальную сеть под protect'ом. Эта граница здесь и проведена: канон знает протокол,
// модуль даёт транспорт.
//
// ⛔ Копию этого файла в своём модуле не заводи. Он инжектируется в КАЖДЫЙ модуль с `"socks5": true`,
// и вторая реализация того же протокола рядом неизбежно с ним разойдётся — не в сборке, а в
// рантайме на чужой машине.
//
// Тонкие места, которые тут решены и которые копия почти наверняка решит иначе:
//   - `CloseWrite` апстриму — через интерфейсную проверку, а не type-assert к `*net.TCPConn`:
//     у in-tunnel модулей апстрим это `*gonet.TCPConn` из netstack, assert к `*net.TCPConn` на
//     нём не сработает;
//   - accept-петля выходит по `net.ErrClosed` и ТОЛЬКО по нему: выход на любой ошибке убивает
//     SOCKS-фронт от транзиентного EMFILE, а невыход — оставляет вечный горячий цикл на закрытом
//     листенере;
//   - UDP-ассоциация несёт `readyCh` (горутина приёма реально встала в `Read` ДО первого
//     исходящего пакета), счётчики pkts/bytes и РАЗДЕЛЬНЫЕ parseFails/famRejects/dialFails —
//     «датаграмма битая», «адресат вне достижимых семей» и «дозвон не удался» суть три разных
//     диагноза, и слитые в один счётчик они перестают что-либо значить.

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// ── Коды и элементарные операции протокола ────────────────────────────────────────────────────

const (
	socksCmdConnect      = 0x01
	socksCmdUDPAssociate = 0x03
)

// socksRep — ответ SOCKS5: VER REP RSV ATYP(ipv4) BND.ADDR(0.0.0.0) BND.PORT(0).
func socksRep(rep byte) []byte { return []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0} }

// socksReadLP — поле с однобайтовым префиксом длины (имя пользователя, пароль, домен).
func socksReadLP(br *bufio.Reader) ([]byte, error) {
	n, err := br.ReadByte()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	_, err = io.ReadFull(br, buf)
	return buf, err
}

// ── Рукопожатие и разбор запроса ──────────────────────────────────────────────────────────────

// socksRequest — разобранный запрос. Host непуст ровно тогда, когда клиент прислал ДОМЕН
// (ATYP 0x03); иначе валиден IP. Отдельного поля `isIP` нет намеренно: оно выводится, а
// выводимое поле — двойник, который однажды разойдётся со своим источником.
type socksRequest struct {
	Cmd  byte
	Host string
	IP   netip.Addr
	Port uint16
}

// IsIP — клиент прислал литерал, а не домен (резолвить нечего).
func (r socksRequest) IsIP() bool { return r.Host == "" }

// TargetLabel — что писать в лог как адресата: домен, если клиент прислал его, иначе IP.
// Секретов не несёт (адрес назначения хост и так знает), но без него в логе не отличить обрыв
// до сервера каскада от обрыва до обычного адресата.
func (r socksRequest) TargetLabel() string {
	if r.Host != "" {
		return r.Host
	}
	return r.IP.String()
}

// socksHandshake — приветствие → user/pass → запрос. Отказы (неподдерживаемая команда, чужой
// ATYP, неверные креды) отвечает САМ; вызывающему остаётся только закрыть соединение.
// Возвращает ok=false, если дальше говорить не о чем.
func socksHandshake(c net.Conn, br *bufio.Reader, user, pass string) (socksRequest, bool) {
	var req socksRequest

	// greeting: VER NMETHODS METHODS — требуем user/pass (0x02).
	if b, err := br.ReadByte(); err != nil || b != 0x05 {
		return req, false
	}
	nm, err := br.ReadByte()
	if err != nil {
		return req, false
	}
	if _, err := io.CopyN(io.Discard, br, int64(nm)); err != nil {
		return req, false
	}
	if _, err := c.Write([]byte{0x05, 0x02}); err != nil {
		return req, false
	}

	// auth: VER ULEN USER PLEN PASS (RFC 1929).
	if b, err := br.ReadByte(); err != nil || b != 0x01 {
		return req, false
	}
	gu, err := socksReadLP(br)
	if err != nil {
		return req, false
	}
	gp, err := socksReadLP(br)
	if err != nil {
		return req, false
	}
	if string(gu) != user || string(gp) != pass {
		_, _ = c.Write([]byte{0x01, 0x01}) // auth failure
		return req, false
	}
	if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
		return req, false
	}

	// request: VER CMD RSV ATYP.
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return req, false
	}
	req.Cmd = hdr[1]
	if hdr[0] != 0x05 || (req.Cmd != socksCmdConnect && req.Cmd != socksCmdUDPAssociate) {
		_, _ = c.Write(socksRep(0x07)) // command not supported
		return req, false
	}
	// DST.ADDR + DST.PORT. Для CONNECT это цель; для UDP ASSOCIATE — заявленный клиентом source
	// (обычно 0.0.0.0:0), который никем не используется, но байты вычитать обязаны.
	switch hdr[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return req, false
		}
		req.IP, _ = netip.AddrFromSlice(b)
	case 0x03:
		b, err := socksReadLP(br)
		if err != nil {
			return req, false
		}
		req.Host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return req, false
		}
		req.IP, _ = netip.AddrFromSlice(b)
	default:
		_, _ = c.Write(socksRep(0x08)) // address type not supported
		return req, false
	}
	pp := make([]byte, 2)
	if _, err := io.ReadFull(br, pp); err != nil {
		return req, false
	}
	req.Port = uint16(pp[0])<<8 | uint16(pp[1])
	return req, true
}

// ── Accept-петля ──────────────────────────────────────────────────────────────────────────────

// serveSocksListener — принимает соединения и отдаёт их [handle] в своей горутине.
//
// Выход ТОЛЬКО на закрытом листенере. Транзиентная ошибка Accept (EMFILE и подобное) петлю не
// роняет — иначе один всплеск дескрипторов гасит SOCKS-фронт модуля навсегда; но и вечно
// крутиться на закрытом листенере нельзя. Обе копии до сведения умели ровно по одной половине.
func serveSocksListener(ln net.Listener, handle func(net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("[SOCKS] accept: %v", err)
			time.Sleep(200 * time.Millisecond)
			continue
		}
		go handle(c)
	}
}

// ── Реле ──────────────────────────────────────────────────────────────────────────────────────

// relayCopy — как io.Copy(dst, src), но РАЗДЕЛЬНО возвращает ошибку ЧТЕНИЯ из src (апстрим) и
// ошибку ЗАПИСИ в dst (клиент). `io.Copy` их не различает (одна error на обе стороны), а именно
// это различие определяет, чем закрывать клиентское соединение. io.EOF — не ошибка: это
// корректный конец потока.
func relayCopy(dst io.Writer, src io.Reader) (n int64, readErr, writeErr error) {
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			n += int64(nw)
			if ew != nil {
				return n, nil, ew
			}
			if nw != nr {
				return n, nil, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return n, nil, nil
			}
			return n, er, nil
		}
	}
}

// closeWriteIfPossible — half-close, если сторона его умеет. Через интерфейс, а не через
// type-assert к `*net.TCPConn`: у in-tunnel модулей апстрим — netstack'овый `*gonet.TCPConn`,
// у passthrough — обычный `*net.TCPConn`; метод есть у обоих, конкретный тип разный.
func closeWriteIfPossible(c interface{}) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// relayBidi — двунаправленное реле CONNECT-соединения с честной политикой закрытия.
//
// ⚠ ОШИБКУ АПСТРИМА НЕЛЬЗЯ ВЫДАВАТЬ ЗА ШТАТНЫЙ КОНЕЦ ПОТОКА. Исходно обе `io.Copy` глотали
// ошибку, и на ЛЮБОМ исходе чтения апстрима клиенту делался `CloseWrite()` — для клиента это
// неотличимо от «сервер корректно закрыл соединение»: он читает чистый EOF. То есть транзиентный
// обрыв внутри туннеля модуль САМ переводил в «апстрим ответил и закончил».
//
// Цена этой лжи измерена построчно на живом каскаде (qWDTT→vless/trojan): проба
// отклика получала `urlTest: Head "...": EOF`, а `classifyUrlTestError` относит EOF к -4 =
// «post-handshake, адресат отверг», то есть к классу «туннель жив, виноват адресат»; в логе ядра
// рядом стояло `copy STALLED tag=proxy-cascade`. Мы кормили собственную классификацию собственным
// же искажением.
//
// Теперь: чистый конец потока → half-close; ошибка ЧТЕНИЯ апстрима → `SetLinger(0)`+`Close()`,
// то есть RST (клиент видит обрыв, а не «сервер закончил»); ошибка ЗАПИСИ клиенту (он ушёл
// первым — штатный `write: broken pipe` на loopback) → молча: первая версия фикса делала RST на
// любую ошибку, и живой лог сразу показал, что подавляющее большинство ошибок здесь именно
// такие, то есть RST был ложной тревогой на ровном месте.
func relayBidi(client net.Conn, br *bufio.Reader, up net.Conn, target string, since time.Time) {
	type copyOutcome struct {
		n   int64
		err error
	}
	upDone := make(chan copyOutcome, 1)
	go func() {
		n, err := io.Copy(up, br)
		if err == nil {
			// Клиент честно закончил передачу — сигналим апстриму конец потока. Безусловный
			// `CloseWrite()` здесь был багом: оборвавшегося клиента модуль выдавал апстриму за
			// корректно закончившего.
			closeWriteIfPossible(up)
		}
		upDone <- copyOutcome{n, err}
	}()
	nDown, readErr, writeErr := relayCopy(client, up)
	switch {
	case readErr != nil:
		if t, ok := client.(*net.TCPConn); ok {
			_ = t.SetLinger(0)
		}
		_ = client.Close()
	case writeErr != nil:
		// Клиент ушёл первым — сообщать уже некому и незачем.
	default:
		closeWriteIfPossible(client)
	}
	upRes := <-upDone
	if readErr != nil || upRes.err != nil {
		// Только на ошибке: на здоровом соединении лог молчит.
		log.Printf("[RELAY] target=%s down=%dB downReadErr=%v downWriteErr=%v up=%dB upErr=%v lifetime=%v",
			target, nDown, readErr, writeErr, upRes.n, upRes.err, time.Since(since))
	}
}

// ── UDP ASSOCIATE (RFC 1928 §7) ───────────────────────────────────────────────────────────────

// socksResolver — что для модуля значит «резолв имени». У каждого своё: qWDTT резолвит через
// свою WG-туннельную netstack (домен нужен ВНУТРИ уже установленного туннеля), echo — off-tunnel
// через protected-путь (домен — реальный адрес назначения в интернете). Канон об этом ничего не
// знает, только зовёт интерфейс.
type socksResolver interface {
	LookupHost(host string) ([]string, error)
}

// errSocksTargetUnreachable — адресат вне семей, которые транспорт модуля физически несёт
// (например IPv6-цель при v4-only туннеле). Отдельная от прочих ошибка, потому что «датаграмма
// битая», «дозвон не удался» и «до этой семьи отсюда пути нет» — три РАЗНЫХ диагноза, и слить их
// в один счётчик значит потерять различие ровно там, где по логу и разбираются.
var errSocksTargetUnreachable = errors.New("socks5: no route to this address family")

// socksUDPTransport — всё, что канону нужно от модуля для UDP-реле.
type socksUDPTransport interface {
	socksResolver
	// DialUDPTarget — дозвон до цели средствами модуля. Вернуть errSocksTargetUnreachable,
	// если семья адреса транспорту недоступна (см. её доккомментарий).
	DialUDPTarget(dst netip.AddrPort) (net.Conn, error)
}

// udpAssocSeq — монотонный счётчик для тега #N в UDPASSOC-логах: несколько ассоциаций одного
// клиента могут жить и умирать внахлёст, без id их не различить в общем логе.
var udpAssocSeq int64

// serveSocksUDPAssociate — стандартное SOCKS5 UDP-реле:
//  1. биндим loopback-UDP relay (хост шлёт сюда SOCKS5-UDP-датаграммы);
//  2. отвечаем control-conn'у BND.ADDR=127.0.0.1:relayPort;
//  3. на каждую датаграмму: разбор заголовка → dial цели средствами модуля → реле; ответы
//     оборачиваем обратно в заголовок и шлём клиенту;
//  4. relay живёт пока жив TCP-control-conn (его закрытие хостом = конец ассоциации).
//
// Per-target conn кэшируются (обычно цель одна — сервер каскада). Loopback-relay не нуждается в
// protect (127.0.0.1 в TUN не уходит); изоляцию дозвона до цели обеспечивает сам модуль.
func serveSocksUDPAssociate(ctrl net.Conn, br *bufio.Reader, t socksUDPTransport) {
	assocStart := time.Now()
	assocID := atomic.AddInt64(&udpAssocSeq, 1)
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		log.Printf("UDPASSOC #%d ListenUDP FAILED err=%v", assocID, err)
		_, _ = ctrl.Write(socksRep(0x01))
		return
	}
	defer relay.Close()
	rp := relay.LocalAddr().(*net.UDPAddr).Port
	log.Printf("UDPASSOC #%d OPEN relayPort=%d ctrlRemote=%v ctrlLocal=%v", assocID, rp, ctrl.RemoteAddr(), ctrl.LocalAddr())
	// reply: VER REP RSV ATYP(ipv4) BND.ADDR(127.0.0.1) BND.PORT(relayPort)
	if _, err := ctrl.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(rp >> 8), byte(rp)}); err != nil {
		log.Printf("UDPASSOC #%d reply write FAILED err=%v lifetime=%v", assocID, err, time.Since(assocStart))
		return
	}

	var mu sync.Mutex
	targets := map[netip.AddrPort]net.Conn{}
	var clientAddr *net.UDPAddr
	var pktsIn, pktsOut, bytesIn, bytesOut int64
	var parseFails, dialFails, famRejects int64
	defer func() {
		mu.Lock()
		for _, u := range targets {
			_ = u.Close()
		}
		nTargets := len(targets)
		targets = nil
		mu.Unlock()
		log.Printf("UDPASSOC #%d CLOSE lifetime=%v pktsIn=%d pktsOut=%d bytesIn=%d bytesOut=%d parseFails=%d famRejects=%d dialFails=%d targets=%d",
			assocID, time.Since(assocStart), atomic.LoadInt64(&pktsIn), atomic.LoadInt64(&pktsOut),
			atomic.LoadInt64(&bytesIn), atomic.LoadInt64(&bytesOut), atomic.LoadInt64(&parseFails),
			atomic.LoadInt64(&famRejects), atomic.LoadInt64(&dialFails), nTargets)
	}()

	// Закрытие control-conn'а (хост завершил ассоциацию) → рвём relay (разблокирует ReadFromUDP).
	go func() {
		n, cerr := io.Copy(io.Discard, br)
		log.Printf("UDPASSOC #%d ctrl-conn EOF (closing relay) drainedBytes=%d err=%v lifetime=%v", assocID, n, cerr, time.Since(assocStart))
		_ = relay.Close()
	}()

	buf := make([]byte, 64*1024)
	for {
		n, src, err := relay.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDPASSOC #%d ReadFromUDP FAILED (loop exit) err=%v lifetime=%v", assocID, err, time.Since(assocStart))
			return
		}
		atomic.AddInt64(&pktsIn, 1)
		atomic.AddInt64(&bytesIn, int64(n))
		mu.Lock()
		if clientAddr == nil {
			clientAddr = src
			log.Printf("UDPASSOC #%d first client datagram from=%v n=%d elapsed=%v", assocID, src, n, time.Since(assocStart))
		}
		mu.Unlock()
		dst, data, ok := parseSocksUDP(buf[:n], t)
		if !ok {
			atomic.AddInt64(&parseFails, 1)
			log.Printf("UDPASSOC #%d parseSocksUDP FAILED n=%d", assocID, n)
			continue
		}
		mu.Lock()
		uc := targets[dst]
		mu.Unlock()
		if uc == nil {
			dialStart := time.Now()
			nc, derr := t.DialUDPTarget(dst)
			if derr != nil {
				if errors.Is(derr, errSocksTargetUnreachable) {
					atomic.AddInt64(&famRejects, 1)
					log.Printf("UDPASSOC #%d target UNREACHABLE dst=%v err=%v", assocID, dst, derr)
				} else {
					atomic.AddInt64(&dialFails, 1)
					log.Printf("UDPASSOC #%d target dial FAILED dst=%v err=%v dialElapsed=%v", assocID, dst, derr, time.Since(dialStart))
				}
				continue
			}
			log.Printf("UDPASSOC #%d target dial OK dst=%v dialElapsed=%v", assocID, dst, time.Since(dialStart))
			uc = nc
			mu.Lock()
			targets[dst] = uc
			mu.Unlock()
			// pump target → client: ответы оборачиваем в SOCKS5-UDP-заголовок с этим target'ом.
			//
			// readyCh (cold-start race): планирование горутины не гарантирует, что её
			// `u.Read(rb)` реально встал в приём ДО того как первый исходящий пакет уйдёт ниже.
			readyCh := make(chan struct{})
			go func(u net.Conn, tgt netip.AddrPort) {
				h := buildSocksUDPHeader(tgt)
				rb := make([]byte, 64*1024)
				outSeq := int64(0)
				close(readyCh)
				for {
					m, rerr := u.Read(rb)
					if rerr != nil {
						log.Printf("UDPASSOC #%d target READ ended dst=%v err=%v afterPkts=%d elapsed=%v", assocID, tgt, rerr, outSeq, time.Since(assocStart))
						return
					}
					outSeq++
					atomic.AddInt64(&pktsOut, 1)
					atomic.AddInt64(&bytesOut, int64(m))
					mu.Lock()
					ca := clientAddr
					mu.Unlock()
					if ca == nil {
						continue
					}
					out := make([]byte, 0, len(h)+m)
					out = append(out, h...)
					out = append(out, rb[:m]...)
					if _, werr := relay.WriteToUDP(out, ca); werr != nil {
						log.Printf("UDPASSOC #%d relay.WriteToUDP(client) FAILED dst=%v payloadLen=%d totalLen=%d err=%v", assocID, tgt, m, len(out), werr)
					}
				}
			}(uc, dst)
			// Ждём пока горутина реально дойдёт до Read — ТОЛЬКО на свежем dial'е: первый пакет
			// уходит именно отсюда же ниже. Последующие пакеты того же target'а этой веткой не
			// проходят — ждать нечего, горутина давно жива.
			<-readyCh
		}
		// Ошибку Write НЕ глотаем: без неё устойчивая in/out асимметрия размеров необъяснима —
		// реальная причина (EMSGSIZE и т.п.) не сохраняется нигде, и MTU-гипотезы проверяются
		// вслепую.
		if _, werr := uc.Write(data); werr != nil {
			log.Printf("UDPASSOC #%d target.Write FAILED dst=%v payloadLen=%d err=%v", assocID, dst, len(data), werr)
		}
	}
}

// ── Чисто-функциональный wire-формат UDP-датаграммы ───────────────────────────────────────────

// parseSocksUDP — SOCKS5 UDP-датаграмма (RSV[2] FRAG[1] ATYP[1] DST.ADDR DST.PORT DATA) →
// (target, payload). Фрагментация (FRAG != 0) не поддерживается — датаграмма отбрасывается.
// Домен-таргеты (ATYP 0x03) резолвятся через переданный резолвер (см. [socksResolver]).
func parseSocksUDP(p []byte, resolver socksResolver) (netip.AddrPort, []byte, bool) {
	if len(p) < 4 || p[2] != 0x00 {
		return netip.AddrPort{}, nil, false
	}
	off := 4
	var ip netip.Addr
	switch p[3] {
	case 0x01:
		if len(p) < off+4+2 {
			return netip.AddrPort{}, nil, false
		}
		ip, _ = netip.AddrFromSlice(p[off : off+4])
		off += 4
	case 0x04:
		if len(p) < off+16+2 {
			return netip.AddrPort{}, nil, false
		}
		ip, _ = netip.AddrFromSlice(p[off : off+16])
		off += 16
	case 0x03:
		if len(p) < off+1 {
			return netip.AddrPort{}, nil, false
		}
		l := int(p[off])
		off++
		if len(p) < off+l+2 {
			return netip.AddrPort{}, nil, false
		}
		host := string(p[off : off+l])
		off += l
		ips, err := resolver.LookupHost(host)
		if err != nil || len(ips) == 0 {
			return netip.AddrPort{}, nil, false
		}
		ip, _ = netip.ParseAddr(ips[0])
	default:
		return netip.AddrPort{}, nil, false
	}
	port := uint16(p[off])<<8 | uint16(p[off+1])
	off += 2
	return netip.AddrPortFrom(ip, port), p[off:], true
}

// buildSocksUDPHeader — SOCKS5-UDP-заголовок ответа (RSV[2]=0 FRAG[1]=0 ATYP DST.ADDR DST.PORT).
func buildSocksUDPHeader(t netip.AddrPort) []byte {
	a := t.Addr()
	var h []byte
	if a.Is4() {
		v := a.As4()
		h = append([]byte{0, 0, 0, 0x01}, v[:]...)
	} else {
		v := a.As16()
		h = append([]byte{0, 0, 0, 0x04}, v[:]...)
	}
	p := t.Port()
	return append(h, byte(p>>8), byte(p))
}
