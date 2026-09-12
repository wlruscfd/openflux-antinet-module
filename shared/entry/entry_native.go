// SPDX-License-Identifier: MIT

//go:build !android

package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// КАНОН shared/entry — ДЕСКТОПНЫЙ вход модуля (GOOS=windows/linux/darwin).
// Инжектируется build.py в main-пакет КАЖДОГО модуля (гейта нет). Парная android-половина —
// entry_android.go, там модуль — библиотека и argv ему не адресован вовсе.
//
// ⛔ Своей копии не заводи: порядок аргументов и набор parse-only сабкоманд — часть контракта, по
// которому хост форкает helper. Копия расходится с ним молча.
//
// Хост форкает:  helper <configPath> <resolversPath> <profileDir> <protectPath>
//
//	configPath    — ФОЛЛБЭК-путь: реальное содержимое приезжает в ANTINET_MODULE_CONFIG (§3,
//	                секреты мимо диска), см. readConfigForEntry (канон shared/hostproto);
//	resolversPath — доп. файл протокол-специфичного содержимого (модуль волен не использовать);
//	profileDir    — writable-каталог helper'а (маркер ready, логи, состояние);
//	protectPath   — UNIX-сокет protect-сервиса AntiNet.
//
// Слушающий сокет: номер fd в ANTINET_LISTEN_FD, если хост смог его передать (Unix). На Windows
// передать сокет нечем — там приезжает только LISTEN_PORT, и модуль биндит сам (см. openListener).
func main() {
	// parse-only сабкоманды (§2.2) — обслуживаются ДО любой тяжёлой обвязки: ни lifecycle, ни
	// сети, ни сокетов. Отработали → сразу выход.
	if len(os.Args) >= 3 && (os.Args[1] == "summarize" || os.Args[1] == "normalize" || os.Args[1] == "canping") {
		fmt.Println(moduleCall(os.Args[1], os.Args[2]))
		return
	}
	if len(os.Args) < 5 {
		fmt.Fprintln(os.Stderr, "usage: helper <configPath> <resolversPath> <profileDir> <protectPath>")
		os.Exit(2)
	}
	listenFd := 0
	if v := strings.TrimSpace(os.Getenv("ANTINET_LISTEN_FD")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			listenFd = n
		}
	}
	os.Exit(realMain(readConfigForEntry(os.Args[1]), os.Args[2], os.Args[3], os.Args[4], listenFd))
}
