// SPDX-License-Identifier: MIT

//go:build android

package main

// Канонический клиент protect-сервиса AntiNet (SCM_RIGHTS через UNIX-сокет). ОДИН на все модули —
// инжектируется build.py в main-пакет helper'а, как и shared/offtun. Своей копии не пиши: ошибка
// здесь невидима (сравнение `n >= 1` вместо `n == 1`, чтение ответа поверх буфера отправки) — сокет
// просто молча уходит в TUN, ни ошибки, ни ретрая.
//
// Зачем это вообще: helper — отдельный процесс под тем же UID, что AntiNet, и его исходящие
// сокеты по умолчанию уходят в TUN → петля (модуль сам и есть выход из туннеля). Пометить сокет
// снаружи нечем, поэтому helper шлёт свой fd в protect-сервис, а тот применяет SO_MARK.

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

// protectAckSuccess — зеркало libcore `protect.ProtectSuccess` (iota: Failed=0, Success=1).
// Дублируется числом, а не импортом: helper — отдельный Go-модуль, libcore ему недоступен.
const protectAckSuccess byte = 1

const (
	// «Сервиса нет» — редко и дорого: мало попыток, разнесённых во времени.
	protectMaxAttempts = 5
	// «Обрыв» — часто и дёшево, поэтому ограничиваем БЮДЖЕТОМ ВРЕМЕНИ, а не числом попыток.
	// Почему не «5 попыток подряд»: живой замер на телефоне (1756 обменов) поймал регрессию
	// ровно этой формы — 68 обменов исчерпали 5 попыток ЗА 4мс, и 51 из них вернул «protect
	// failed», то есть 2.9% дозвонов получили незащищённый сокет. С лестницей 60/120/180мс
	// пятая попытка не наступала НИ РАЗУ (0 из 539): всплеск успевал рассосаться. Вывод: повтор
	// обязан быть и быстрым, и достаточно долгим — быстрым по первой попытке, долгим суммарно.
	protectTransientBudget  = 250 * time.Millisecond
	protectTransientWaitCap = 32 * time.Millisecond
)

// protectViaService — отправить fd на protect-сервис. `st` может быть nil (модуль не собирает
// диагностику). Второй возврат — сколько попыток реально потребовалось: одна против пяти это
// разница между «сеть тормозит» и «сервис не отвечает».
func protectViaService(path string, fd int, st *protectStat) (bool, int) {
	if path == "" {
		return false, 0
	}
	started := time.Now()
	defer func() {
		if st != nil {
			st.elapsedMs = float64(time.Since(started).Microseconds()) / 1000.0
		}
	}()
	attempt := 0
	// Счётчик ОТДЕЛЬНЫЙ от общего: транзиентные попытки живут по времени, а не по числу, и не
	// должны съедать лимит «сервиса нет». Иначе одна случайная нетранзиентная ошибка посреди
	// транзиентной серии обрывала её досрочно — живой замер поймал выходы на 5-й попытке при
	// израсходованных 15мс из 250мс бюджета.
	hardAttempt := 0
	transientWait := time.Millisecond
	for {
		attempt++
		ok, err := protectOnce(path, fd)
		if ok {
			if st != nil {
				st.attempts = attempt
			}
			return true, attempt
		}
		if st != nil && st.firstErr == "" && err != nil {
			st.firstErr = err.Error()
		}

		if isTransientProtectErr(err) {
			// Обрыв лечится НОВЫМ соединением, а не ожиданием: сервис жив и обслуживает соседние
			// запросы в ту же миллисекунду. Поэтому ПЕРВЫЙ повтор — мгновенный (именно он снял
			// фиксированные 60мс: p90 protect'а 71.4мс → 9.6мс, сквозной p99 20с → 810мс).
			// Дальше — плотная растущая пауза до общего бюджета: всплеск бывает длиннее одной
			// миллисекунды, и сжигать все попытки подряд нельзя (см. комментарий к константам).
			if attempt == 1 {
				continue
			}
			if time.Since(started) >= protectTransientBudget {
				break
			}
			time.Sleep(transientWait)
			if transientWait < protectTransientWaitCap {
				transientWait *= 2
			}
			continue
		}

		// «Сервиса нет» — ждать действительно надо, иначе попытки сгорят за микросекунды и вернут
		// отказ раньше, чем сервис успеет подняться.
		hardAttempt++
		if hardAttempt >= protectMaxAttempts {
			break
		}
		time.Sleep(time.Duration(60*hardAttempt) * time.Millisecond)
	}
	if st != nil {
		st.attempts = attempt
	}
	return false, attempt
}

// errProtectRefused — сервис ОТВЕТИЛ `ProtectFailed`. Отдельный сентинел, а не просто текст:
// по нему классификатор ниже отличает «живой сервис, у которого не вышло ЭТОТ раз» от «сервиса
// нет вовсе». Первое — транзиент (у `do(fd)` внутри сервиса свои вендорские осечки netd),
// второе — повод ждать.
var errProtectRefused = errors.New("protect: сервис ответил отказом")

// isTransientProtectErr — сервис ЖИВ, повтор осмыслен: обрыв уже установленного соединения,
// переполненная очередь listen'а, либо явный отказ в ответе (сервис ответил — значит он есть).
// Всё остальное (сокета нет, некому слушать, права) — ждать.
func isTransientProtectErr(err error) bool {
	return errors.Is(err, unix.EPIPE) ||
		errors.Is(err, unix.ECONNRESET) ||
		errors.Is(err, unix.EAGAIN) ||
		errors.Is(err, unix.EINTR) ||
		errors.Is(err, errProtectRefused)
}

// protectOnce — один SCM_RIGHTS-обмен: AF_UNIX/SOCK_STREAM → Connect → Sendmsg(fd) → ack.
//
// Возвращает ПРИЧИНУ провала, а не голый false: без шага и errno чинить нечего — «очередь
// переполнена» (EPIPE/EAGAIN) и «сервиса нет» (ENOENT/ECONNREFUSED) требуют РАЗНЫХ решений, а
// снаружи выглядят одинаково.
func protectOnce(path string, fd int) (bool, error) {
	s, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return false, fmt.Errorf("socket: %w", err)
	}
	defer unix.Close(s)
	// read/send не должны виснуть, если сервис залип.
	tv := unix.Timeval{Sec: 3}
	_ = unix.SetsockoptTimeval(s, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(s, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
	if err := unix.Connect(s, &unix.SockaddrUnix{Name: path}); err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	if err := unix.Sendmsg(s, []byte{1}, unix.UnixRights(fd), nil, 0); err != nil {
		return false, fmt.Errorf("sendmsg: %w", err)
	}
	// Отдельный буфер под ответ, не тот, что отправляли: иначе легко принять СВОЙ байт за ответ.
	ack := make([]byte, 1)
	n, err := unix.Read(s, ack)
	if err != nil {
		return false, fmt.Errorf("read-ack: %w", err)
	}
	if n < 1 {
		return false, errors.New("read-ack: empty")
	}
	// Байт ответа ЗНАЧИМ: 0 = protect не удался, 1 = удался. Проверять только ДЛИНУ ответа нельзя —
	// тогда явный отказ сервиса читается как успех, сокет считается защищённым и уходит в TUN
	// (петля), причём молча. Живой замер: 25 таких отказов на 399 дозвонов (6%).
	if ack[0] != protectAckSuccess {
		return false, fmt.Errorf("read-ack (%d): %w", ack[0], errProtectRefused)
	}
	return true, nil
}
