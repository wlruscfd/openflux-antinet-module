// SPDX-License-Identifier: MIT

//go:build darwin

// Канонический off-TUN socket-protect — physicalIfaceIndex для macOS (IP_BOUND_IF). ⚠ ТОЛЬКО darwin:
// Windows имеет СВОЙ physicalIfaceIndex в offtun_windows.go (route-table `GetIpForwardTable`), т.к. на
// multi-NIC Windows-хосте этот NIC-перебор выбирал virtual-адаптер (см. offtun_windows.go). На macOS
// multi-NIC редок + нет стенда — heuristic оставлен (если понадобится — портировать route-based).
// Инжектируется build.py (см. offtun_linux.go). package main.
package main

import "net"

// physicalIfaceIndex — индекс физ. сетевого интерфейса (up, не loopback, не AntiNet-TUN). 0 = не нашли.
// AntiNet-TUN исключаем по ФИКС-подсети 172.19.0.0/28 (надёжнее имени: antinet-tun / utunN / Wintun).
// Best-effort: первый подходящий (1-NIC корректно; multi-NIC — приемлемая эвристика).
func physicalIfaceIndex() int {
	ifaces, err := net.Interfaces()
	if err != nil {
		return 0
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, aerr := ifi.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ip4 := ip.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			if ip4[0] == 172 && ip4[1] == 19 && ip4[2] == 0 {
				continue // AntiNet TUN 172.19.0.0/28
			}
			return ifi.Index
		}
	}
	return 0
}
