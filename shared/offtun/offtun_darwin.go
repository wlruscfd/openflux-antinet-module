// SPDX-License-Identifier: MIT

//go:build darwin

// Канонический off-TUN socket-protect для macOS: IP_BOUND_IF (IPv4) / IPV6_BOUND_IF (IPv6) по индексу
// физ-iface, МИМО utun (auto_route) + route-правил (см. offtun_linux.go). Инжектируется build.py.
// Best-effort: фейл setsockopt → продолжаем обычным dial. ⚠ Не валидировано вживую (только cross-compile).
package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func bindFdToPhysicalDarwin(fd int) {
	idx := physicalIfaceIndex()
	if idx <= 0 {
		return
	}
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, idx)
}

// offtunBindControl — форма net.Dialer.Control / ListenConfig.Control (qWDTT-стиль).
func offtunBindControl(network, address string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) { bindFdToPhysicalDarwin(int(fd)) })
}

// offtunBindFd — форма func(fd) bool (masterdns-стиль). true = продолжить dial.
func offtunBindFd(fd int) bool {
	bindFdToPhysicalDarwin(fd)
	return true
}
