// SPDX-License-Identifier: MIT

//go:build unix && !android

package main

// КАНОН shared/dns — резолверы САМОЙ ОС, unix-половина (linux, darwin). Парные
// половины — `dnsshim_system_android.go` и `dnsshim_system_windows.go`, имя и сигнатура там ТЕ ЖЕ,
// поэтому общий код модуля зовёт `systemDNSServers()` без единого build-тега у себя.
//
// ⚠ `&& !android` ОБЯЗАТЕЛЕН: `GOOS=android` активирует и тег `unix`, поэтому без него сюда попал
// бы и Android — а там `/etc/resolv.conf` не существует, и файл отдавал бы пусто, пряча реальный
// источник. Что это за источник — в android-половине.

import (
	"bufio"
	"os"
	"strings"
)

// resolvConfPath — вынесен константой, чтобы тест мог рассказать, ОТКУДА берутся серверы, не
// перечитывая функцию.
const resolvConfPath = "/etc/resolv.conf"

// systemDNSServers — резолверы, настроенные в ОС. Пусто — легитимный ответ (нет файла, нет прав,
// нет ни одной записи `nameserver`): вызывающий обязан считать это за «резолвить нечем», а не за
// повод пойти в обход.
//
// Разбирается ТОЛЬКО `nameserver`: `search`/`options`/`domain` описывают, КАК спрашивать, и этим
// уже занимается сам `net.Resolver` — прокладке нужен лишь адрес, куда отправить пакет.
func systemDNSServers() []string {
	f, err := os.Open(resolvConfPath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		// Комментарий может идти и с `;` — так пишет часть резолвер-демонов.
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
			continue
		}
		out = append(out, fields[1])
	}
	// Ошибку сканера намеренно не отличаем от «нет записей»: обрезанный на полуслове resolv.conf
	// даёт ровно то же, что и пустой, — неполный список, которому нельзя доверять как полному.
	return normalizeDNSServers(out)
}
