// SPDX-License-Identifier: MIT

//go:build windows

// Канонический off-TUN socket-protect для Windows: IP_UNICAST_IF (IPv4) / IPV6_UNICAST_IF (IPv6) —
// привязка исходящего сокета к ФИЗ-iface МИМО Wintun (auto_route) + route-правил (включая port:53→
// hijack-dns; см. offtun_linux.go). Инжектируется build.py. Применяется через nativeclient
// protectedDialUDP/ListenUDP (Dialer.Control).
//
// ⚠ Физ-iface определяется по ТАБЛИЦЕ МАРШРУТОВ (`GetIpForwardTable`), НЕ перебором net.Interfaces:
// на multi-NIC хосте (VMware/Hyper-V virtual switches + реальный NIC) наивный «первый up не-loopback»
// выбирает VIRTUAL-адаптер (host-only 192.168.x) → UDP в никуда → 0 резолверов.
// Берём ifIndex дефолт-маршрута 0.0.0.0/0 (Wintun ставит 0.0.0.0/1+128.0.0.0/1, НЕ точный /0 → его
// дефолт не мешает) с наименьшей метрикой, исключая Wintun (172.19.0.0/28). Это аналог Linux
// /proc/net/route. IP_UNICAST_IF (IPv4) принимает индекс в СЕТЕВОМ порядке байт (htonl); IPv6 — host.
// Best-effort: фейл/0 → обычный dial (без регресса).
package main

import (
	"math/bits"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	ipUnicastIf   = 31 // IP_UNICAST_IF   (IPPROTO_IP)
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF (IPPROTO_IPV6)
)

var (
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpForwardTable = iphlpapi.NewProc("GetIpForwardTable")
)

// mibIPForwardRow — MIB_IPFORWARDROW (14×DWORD, без паддинга). Нужны Dest/Mask/IfIndex/Metric1.
type mibIPForwardRow struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

// wintunIfIndex — ifIndex адаптера AntiNet-TUN (IP 172.19.0.0/28) для исключения из дефолт-маршрутов. -1 = нет.
func wintunIfIndex() int {
	ifaces, err := net.Interfaces()
	if err != nil {
		return -1
	}
	for _, ifi := range ifaces {
		addrs, _ := ifi.Addrs()
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip4 := ip.To4(); ip4 != nil && ip4[0] == 172 && ip4[1] == 19 && ip4[2] == 0 {
				return ifi.Index
			}
		}
	}
	return -1
}

// physicalIfaceIndex — ifIndex физ. дефолт-маршрута (dest=0.0.0.0 mask=0.0.0.0, min metric), исключая
// Wintun. 0 = не нашли (→ обычный dial). Аналог Linux physicalDefaultIface (route-table, не NIC-перебор).
func physicalIfaceIndex() int {
	var size uint32
	// 1-й вызов: pTable=NULL → ERROR_INSUFFICIENT_BUFFER + размер.
	procGetIpForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if size == 0 {
		return 0
	}
	buf := make([]byte, size)
	r1, _, _ := procGetIpForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if r1 != 0 { // не NO_ERROR
		return 0
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0])) // dwNumEntries
	if num == 0 {
		return 0
	}
	rows := unsafe.Slice((*mibIPForwardRow)(unsafe.Pointer(&buf[4])), int(num))
	wintun := wintunIfIndex()
	best := 0
	bestMetric := ^uint32(0)
	for i := 0; i < int(num); i++ {
		row := rows[i]
		if row.ForwardDest != 0 || row.ForwardMask != 0 { // не точный дефолт 0.0.0.0/0
			continue
		}
		if wintun >= 0 && int(row.ForwardIfIndex) == wintun {
			continue // Wintun-дефолт (если вдруг есть) — пропускаем
		}
		if row.ForwardMetric1 < bestMetric {
			bestMetric = row.ForwardMetric1
			best = int(row.ForwardIfIndex)
		}
	}
	return best
}

func bindHandleToPhysical(h windows.Handle) {
	idx := physicalIfaceIndex()
	if idx <= 0 {
		return
	}
	// IPv4: индекс в network byte order (htonl); IPv6: host order. Best-effort (фейл игнорим).
	// IP_UNICAST_IF задаёт egress-интерфейс; для wildcard-сокета (0.0.0.0) source-IP
	// тоже берётся с этого интерфейса → ответы резолверов возвращаются на физ-адаптер.
	// ⚠ НЕ делать windows.Bind(source) в Control-callback: для ListenUDP-сокетов (RX/TX-
	// воркеры резолвера, async_runtime.go) ListenConfig биндит laddr ПОСЛЕ Control → наш
	// ранний Bind конфликтует (WSAEINVAL) → ListenPacket падает → весь тоннель мёртв.
	// Корень leak'а был НЕ в source, а в build-tag protect.go (linux||android → на Windows
	// шёл stub без protect вовсе); IP_UNICAST_IF достаточно (egress+source).
	_ = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(bits.ReverseBytes32(uint32(idx))))
	_ = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIf, idx)
}

// offtunBindControl — форма net.Dialer.Control / ListenConfig.Control (qWDTT-стиль).
func offtunBindControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) { bindHandleToPhysical(windows.Handle(fd)) })
}

// offtunBindFd — форма func(fd) bool (masterdns-стиль). true = продолжить dial.
func offtunBindFd(fd int) bool {
	bindHandleToPhysical(windows.Handle(uintptr(uint32(fd))))
	return true
}
