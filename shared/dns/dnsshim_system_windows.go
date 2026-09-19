// SPDX-License-Identifier: MIT

//go:build windows

package main

// КАНОН shared/dns — резолверы САМОЙ ОС, windows-половина. Парная unix-половина —
// `dns_system_unix.go`, имя и сигнатура там ТЕ ЖЕ, поэтому общий код модуля зовёт
// `systemDNSServers()` без единого build-тега у себя.
//
// ⛔ БЕРЁМ DNS ТОЛЬКО У ФИЗИЧЕСКОГО АДАПТЕРА, не «все, что отдала ОС». Wintun (auto_route) — такой
// же адаптер в глазах `GetAdaptersAddresses`, и его DNS ведут ВНУТРЬ туннеля. Взяв список целиком,
// прокладка вернула бы резолверы того самого туннеля, ради обхода которого она и существует, —
// причём молча, потому что запрос к ним формально успешен.
//
// Индекс физ-адаптера НЕ определяем заново: `physicalIfaceIndex()` из `shared/offtun` уже решает
// ровно эту задачу и решает её по ТАБЛИЦЕ МАРШРУТОВ, а не перебором `net.Interfaces` — на
// multi-NIC хосте (VMware/Hyper-V + реальный NIC) наивный перебор выбирает виртуальный адаптер.
// `shared/offtun` инжектируется ВСЕГДА (гейта нет), поэтому функция здесь доступна по построению.

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ifOperStatusUp — IF_OPER_STATUS.IfOperStatusUp из ifdef.h. Литералом, а не через x/sys: там этой
// константы нет, а заводить ради одного сравнения свой пакет незачем.
const ifOperStatusUp = 1

// systemDNSServers — резолверы, которые ОС назначила ФИЗИЧЕСКОМУ адаптеру. Пусто — легитимный
// ответ (физ-адаптер не определился, адаптер не up, DNS не назначены): вызывающий обязан считать
// это за «резолвить нечем», а не за повод пойти в обход.
func systemDNSServers() []string {
	physIdx := physicalIfaceIndex()
	if physIdx <= 0 {
		// Физ-адаптер не определился — а значит любой список, который мы могли бы собрать,
		// пришлось бы брать вслепую, вместе с туннельным. Лучше отдать пусто.
		return nil
	}

	// Всё, кроме DNS, пропускаем: адреса/имена адаптеров нам не нужны, а на хосте с десятком
	// виртуальных адаптеров они заметно раздувают буфер.
	const flags = windows.GAA_FLAG_SKIP_UNICAST |
		windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST |
		windows.GAA_FLAG_SKIP_FRIENDLY_NAME

	// 1-й вызов: буфер nil → ERROR_BUFFER_OVERFLOW и нужный размер. Код ошибки не разбираем —
	// значим только размер (тот же приём, что у `physicalIfaceIndex`'s `GetIpForwardTable`).
	var size uint32
	_ = windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, nil, &size)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, aa, &size); err != nil {
		return nil
	}

	var out []string
	for ; aa != nil; aa = aa.Next {
		if aa.OperStatus != ifOperStatusUp {
			continue
		}
		// IPv4 и IPv6 у одного адаптера живут под РАЗНЫМИ индексами, и физическим может
		// оказаться любой из них — сверяем оба.
		if int(aa.IfIndex) != physIdx && int(aa.Ipv6IfIndex) != physIdx {
			continue
		}
		for dns := aa.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil || ip.IsUnspecified() || isUnusableWindowsDNS(ip) {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return normalizeDNSServers(out)
}

// isUnusableWindowsDNS — адреса, которые Windows перечисляет как DNS, но дозвониться по ним
// нельзя:
//
//   - `fec0:0:0:ffff::1..3` — site-local ЗАГЛУШКИ, которые Windows подставляет сама, когда
//     IPv6-резолверы не настроены. Живого сервера за ними нет, и попытка стоит полного таймаута
//     на каждом резолве;
//   - link-local (`fe80::/10`) — без zone index (`%N`) адрес неполон, а `SocketAddress.IP()` зону
//     не отдаёт: дозвон по такому адресу не состоится в принципе.
func isUnusableWindowsDNS(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		return false
	}
	return len(ip) == net.IPv6len && ip[0] == 0xfe && ip[1] == 0xc0
}
