// SPDX-License-Identifier: MIT

//go:build !android

package main

// КАНОН shared/lifecycle — десктопная половина (GOOS=windows/linux/darwin).
// Полное обоснование канона — в шапке `lifecycle_android.go`.
//
// `dieWithParent` живёт НЕ здесь, а в `lifecycle_dieparent_linux.go` /
// `lifecycle_dieparent_nonlinux.go`: только он и различается внутри десктопа, а разрезать по
// GOOS весь файл значило бы продублировать две функции ниже (они на всех трёх ОС одинаковые).

import (
	"bufio"
	"os"
)

// protectFromOomKill — no-op: Android-модели LMK/vendor-killer на десктопе нет.
func protectFromOomKill() {}

// startHostEventReader — ЕДИНСТВЕННЫЙ канал событий хоста на десктопе: построчный stdin.
//
// Почему stdin: он уже открыт (`poUsePipes` у хоста), симметричен stdout-протоколу маркеров и не
// страдает от «недренируемый pipe вешает data-plane» — дренирует его ХОСТ, а модуль только читает.
// Сигналов десктопный хост НЕ шлёт вовсе, поэтому обработчик `SIGUSR1` в модуле — мёртвый код.
//
// Каждая прочитанная строка уходит в `handleHostEvent` — его определяет САМ модуль (реакция
// модуля — не канон); канон отвечает только за транспорт. Буфер до 4 МБ: payload действия
// (`ACTION_RESULT|<id>|<base64>`) бывает крупным.
func startHostEventReader() {
	go func() {
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			handleHostEvent(sc.Text())
		}
	}()
}
