// SPDX-License-Identifier: MIT

package main

// КАНОН shared/lifecycle — маркер готовности модуля.
//
// Часть контракта модуля с хостом (MODULE_API §2.6), а не протокола данных, поэтому живёт здесь,
// рядом с остальными примитивами жизненного цикла (`dieWithParent`, `protectFromOomKill`,
// `startHostEventReader`), а не в `shared/socks5`: маркер обязан быть у КАЖДОГО модуля, включая
// те, у кого нашего SOCKS5-фронта нет вовсе (masterdns — вендоренный апстрим со своим SOCKS).
//
// ⛔ Своей копии не пиши. Она выглядит тривиально и ровно поэтому расходится молча: пропущенный
// `MkdirAll`, права 0644 вместо 0600, проглоченная ошибка записи — и невозможность записать маркер
// начинает выглядеть как успешный старт, а хост ждёт модуль до своего READY_TIMEOUT без причины
// в логе.
//
// Файл БЕЗ build-тега: тут нет ничего платформенного, а `lifecycle_*.go`-маска инъекции его
// подхватывает наравне с остальными.

import (
	"os"
	"path/filepath"
	"strconv"
)

// writeReady — маркер готовности, атомарно (.tmp → rename); хост поллит появление файла.
//
// Порт выбирает и знает САМ ХОСТ — слушающим сокетом владеет он (§2.6) и передаёт его модулю
// готовым, так что от модуля нужен только сигнал «поднялся». `socks.port` с номером пишем рядом:
// он копеечен и понятен хостам, которые читают его вместо `ready`.
//
// Ошибка записи `socks.port` намеренно НЕ фатальна (файл нужен только старому хосту), ошибка
// записи `ready` — фатальна и возвращается: без маркера хост будет ждать модуль до собственного
// READY_TIMEOUT и объявит «не запустился», а причина не уйдёт никуда.
func writeReady(dir string, port int) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "socks.port.tmp")
	final := filepath.Join(dir, "socks.port")
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(port)), 0600); err == nil {
		_ = os.Rename(tmp, final)
	}
	tmp = filepath.Join(dir, "ready.tmp")
	final = filepath.Join(dir, "ready")
	if err := os.WriteFile(tmp, []byte("1"), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}
