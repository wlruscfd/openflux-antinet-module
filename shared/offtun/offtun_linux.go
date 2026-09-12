// SPDX-License-Identifier: MIT

//go:build linux && !android

// КАНОНИЧЕСКИЙ off-TUN socket-protect — ЕДИНЫЙ источник для ВСЕХ модулей. build.py ИНЖЕКТИРУЕТ этот
// файл в main-пакет helper'а модуля (module.json "offTun": true) ПЕРЕД `go build` и удаляет ПОСЛЕ —
// никакого дублирования per-module в git. ⚠ Править ТОЛЬКО здесь, НЕ копии в native/<module>/.
// package main — файл копируется прямо в main-пакет helper'а. MODULE_API §4.
//
// ⚠ ЗАЧЕМ: одного sing-box `process_name→direct` на десктопе НЕ хватает.
// Он НЕ спасает резолвер-UDP (StormDNS на :53): route-правило `port:53→hijack-dns` стоит ПЕРЕД
// per-app bypass → DNS перехватывается ДО bypass → не доходит → MTU value=0 → helper не встаёт. И для
// ЭФЕМЕРНЫХ UDP-сокетов process-attribution sing-box в принципе ненадёжна. SO_BINDTODEVICE уводит сокет
// на ФИЗ-iface (ens33/eth0) МИМО antinet-tun и ВСЕХ route-правил (включая hijack). Мирор Android SCM_RIGHTS
// (тот же off-TUN-инвариант, иной механизм). Best-effort: SO_BINDTODEVICE требует CAP_NET_RAW (helper
// форкается root-backend'ом → есть); фейл (не-root) → продолжаем обычным dial (без регресса).
package main

import (
	"bufio"
	"os"
	"strings"
	"syscall"
)

// physicalDefaultIface — имя физ. дефолт-iface из main-таблицы (/proc/net/route, Destination 00000000),
// исключая tun/antinet/lo. auto_route держит СВОЙ default в policy-таблице → физ. default остаётся в main.
func physicalDefaultIface() string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan() // header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[1] != "00000000" { // не default-маршрут
			continue
		}
		iface := fields[0]
		if iface == "lo" || strings.HasPrefix(iface, "tun") || strings.HasPrefix(iface, "antinet") {
			continue
		}
		return iface
	}
	return ""
}

// offtunBindControl — форма net.Dialer.Control / net.ListenConfig.Control (qWDTT-стиль: его data-plane
// принимает protect как Control-функцию). Биндит сокет к физ-iface ДО connect.
func offtunBindControl(network, address string, c syscall.RawConn) error {
	iface := physicalDefaultIface()
	if iface == "" {
		return nil // нет физ-дефолта → обычный dial (не хуже прежнего)
	}
	return c.Control(func(fd uintptr) {
		// best-effort: фейл (нет CAP_NET_RAW) игнорим → dial идёт обычным путём.
		_ = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
	})
}

// offtunBindFd — форма func(fd) bool (masterdns-стиль: nativeclient.Options.Protect). true = продолжить
// dial (protectControl фейлит dial только при false → best-effort всегда true).
func offtunBindFd(fd int) bool {
	if iface := physicalDefaultIface(); iface != "" {
		_ = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
	}
	return true
}
