// SPDX-License-Identifier: MIT

package main

// КАНОН shared/hostproto — ПРОТОКОЛ РАЗГОВОРА С ХОСТОМ целиком. Инжектируется
// build.py в main-пакет КАЖДОГО модуля (гейта нет: без этого не работает ни один).
//
// ⛔ Копию в своём модуле не заводи. Это не «утилитки», а сам контракт: формат конфига, владение
// слушающим сокетом, перечень stdout-маркеров, порядок EVENT_ACK. Копия расходится с контрактом
// молча — сборка проходит, а хост перестаёт понимать модуль.
//
// Здесь лежит ВСЁ, что у модулей было байт-в-байт одинаковым и жило тремя копиями под тремя
// именами (echo `readConfigForEntry` / qWDTT `readModuleConfigContent` / masterdns
// `readModuleConfigContent`; echo `emitEventAck` ≡ masterdns `emitEventAck`; три `handleHostEvent`;
// два `openListener` + qWDTT'шная пара `listen_other.go`/`listen_windows.go`).
//
// Модулю остаётся РОВНО ДВЕ функции, которые канон зовёт, а модуль определяет (см. shared/entry):
//
//	func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int
//	func moduleCall(verb, arg string) string
//
// Файл БЕЗ build-тега: платформенного здесь ничего нет.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── Конфиг от хоста ───────────────────────────────────────────────────────────────────────────

// readConfigForEntry — откуда взять СОДЕРЖИМОЕ конфига в desktop-форме доставки: сначала переменная
// окружения ANTINET_MODULE_CONFIG (base64 от KEY=VALUE-текста), и только если её нет — файл по
// пути-аргументу (обратная совместимость со старым хостом).
//
// Секреты (SOCKS_PASS, апстримный секрет внутри LINK=) не должны касаться диска (MODULE_API §3:
// data/-дерево на Desktop world-readable, на Windows ACL-permissive). В Android-форме этого вопроса
// нет вовсе: содержимое приезжает C-строкой в antinet_module_run.
func readConfigForEntry(path string) string {
	if enc := strings.TrimSpace(os.Getenv("ANTINET_MODULE_CONFIG")); enc != "" {
		if dec, derr := base64.StdEncoding.DecodeString(enc); derr == nil {
			return string(dec)
		} else {
			log.Printf("decode ANTINET_MODULE_CONFIG: %v", derr)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("read config %s: %v", path, err)
		return ""
	}
	return string(data)
}

// parseConfig — разбор KEY=VALUE-текста (# = комментарий). Формат ЕДИН на обеих платформах и для
// обеих форм доставки: LISTEN_PORT / SOCKS_USER / SOCKS_PASS / LINK / DNS_SERVERS / APP_LANG /
// START_REASON / MODULE_STATE / SETTING_<key> — их пишет и Android ModuleManager, и Desktop-хост.
func parseConfig(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			out[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
		}
	}
	return out
}

// ── Слушающий SOCKS5-сокет ────────────────────────────────────────────────────────────────────

// openListener — СОКЕТ СОЗДАЁТ ХОСТ и передаёт готовым (MODULE_API §2.6): Desktop-Unix —
// наследованием fd (номер в ANTINET_LISTEN_FD), Android-слот — тем же номером параметром C-ABI.
// Хост знает порт сразу и авторитетно, а сокет ПЕРЕЖИВАЕТ смерть/подмену модуля (входящие копятся
// в backlog ядра, sing-box не получает ECONNREFUSED) — именно это делает восстановление «коротким
// сетевым сбоем» и убирает класс гонок ре-бинда того же порта.
//
// ⚠ fd ПЕРЕДАН (>0) ⇒ усыновляем, и фоллбэка на net.Listen тут НЕТ намеренно: тот же порт держит
// хост, повторный bind гарантированно даст EADDRINUSE, а хост увидит бесконечный crash-loop вместо
// честного провала. fd НЕ передан (Windows — там передать сокет нечем; либо старый хост) ⇒ порт
// выбрал хост и прислал в LISTEN_PORT, биндим сами.
//
// ⛔ УСЫНОВЛЕНИЕ ОДНОРАЗОВОЕ — листенер живёт столько же, сколько ПРОЦЕСС. `os.NewFile` забирает
// владение дескриптором, `net.FileListener` его дуплицирует, оригинал закрывается: второй
// FileListener на то же ЧИСЛО обречён на `invalid argument`. Держи `net.Listener` в переменной
// уровня процесса и НЕ закрывай его при внутренних перезапусках сессии.
func openListener(port, listenFd int) (net.Listener, error) {
	if listenFd <= 0 {
		return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	}
	f := os.NewFile(uintptr(listenFd), "antinet-socks")
	if f == nil {
		return nil, fmt.Errorf("listenFd=%d: os.NewFile вернул nil", listenFd)
	}
	ln, lerr := net.FileListener(f)
	// FileListener ДУПЛИЦИРУЕТ дескриптор — оригинал наш и больше не нужен.
	_ = f.Close()
	if lerr != nil {
		return nil, fmt.Errorf("усыновление listenFd=%d: %w", listenFd, lerr)
	}
	return ln, nil
}

// ── Маркеры stdout (MODULE_API §2.9/§2.13) ────────────────────────────────────────────────────
//
// Хост ловит маркеры через contains, а не startsWith, поэтому таймстамп-префикс парсинг не ломает.
// Таймстампит строки САМ модуль: хост пишет stdout в файл как есть, построчно его не обрабатывая.
//
// ⚠ Граница локализации проходит по ПРИЁМНИКУ, а не по маркеру (§2.9): текст ПОСЛЕ тега в
// PROGRESS|/LOG| юзер видит тостом и на экране «Логи», поэтому модуль обязан выбирать его по
// APP_LANG. А сами ТЕГИ, таймстамп-префикс, `detail` у STATUS| и весь log.Printf — ASCII/английский
// всегда: первые разбирает хост, вторые читает разработчик грепом по helper.stdout.log, а
// grep-тулинг ломается на не-ASCII.

const markerTimeFormat = "15:04:05.000000"

// emitProgress — PROGRESS|<текст>: transient-тост ТОЛЬКО на connect-пути. Мид-сессионные
// PROGRESS-строки хост структурно отбрасывает — показать их некому.
//
// Подряд идущий ОДИНАКОВЫЙ текст не печатается: у модуля, который гонит через прогресс свои
// milestone-строки (qWDTT тщит туда весь свой лог через classifyProgress), повтор одной и той же
// фразы иначе заливает helper.stdout.log, который потом читают глазами.
var progressLast string

func emitProgress(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if msg == "" || msg == progressLast {
		return
	}
	progressLast = msg
	fmt.Printf("%s PROGRESS|%s\n", time.Now().Format(markerTimeFormat), msg)
	_ = os.Stdout.Sync()
}

// emitLog — LOG|<текст>: ПОСТОЯННАЯ, листаемая запись в визуальном логе AntiNet (экран «Логи» +
// log_*.txt). Для событий, на которые юзер захочет посмотреть ПОЗЖЕ (хендовер, деградация,
// мид-сессионное действие) — не для высокочастотного per-connection шума (тому место в log.Printf,
// который остаётся только в helper.stdout.log).
func emitLog(format string, args ...any) {
	fmt.Printf("%s LOG|%s\n", time.Now().Format(markerTimeFormat), fmt.Sprintf(format, args...))
	_ = os.Stdout.Sync()
}

// Состояния маркера STATUS| (MODULE_API §2.13). Перечень ЗАКРЫТЫЙ: хост принимает решения только
// по этим значениям, неизвестное игнорирует с предупреждением.
const (
	statusOK       = "ok"       // работаю штатно
	statusWaiting  = "waiting"  // ЖДУ ВНЕШНИЙ ресурс: квоту, очередь, снятие rate-limit
	statusDegraded = "degraded" // работаю, но хуже обычного
	statusFatal    = "fatal"    // сам не поднимусь, нужно пересоздание/вмешательство юзера
)

// emitStatus — STATUS|<state>[|<detail>]: ТИПИЗИРОВАННОЕ состояние живого helper'а. Это не лог: по
// нему хост решает, чем лечить отказ — щадящим сигналом или relaunch'ем. Состояние ЛИПКОЕ до
// следующего маркера: прислал waiting — обязан прислать ok, когда ресурс получен.
//
// `detail` — свободный ASCII-текст ДЛЯ ЛОГА; '|' и переносы строк из него убираются, потому что
// первый — разделитель записи, второй — её конец.
//
// ⚠ Повтор ОДНОГО И ТОГО ЖЕ состояния подряд не печатается — этого прямо требует §2.13 («дедуп на
// стороне модуля»). Точка «работа пошла» срабатывает часто (у qWDTT `ok` эмитится на каждом из 9
// воркеров и на каждой переустановке DTLS), и без гасителя это поток одинаковых строк. Решения хост
// принимает по `state`, поэтому смена `detail` при том же состоянии повтором не считается.
var lastEmittedStatus string

func emitStatus(state string, detail string) {
	if state == lastEmittedStatus {
		return
	}
	lastEmittedStatus = state
	detail = strings.ReplaceAll(strings.ReplaceAll(detail, "|", "/"), "\n", " ")
	if detail != "" {
		fmt.Printf("%s STATUS|%s|%s\n", time.Now().Format(markerTimeFormat), state, detail)
	} else {
		fmt.Printf("%s STATUS|%s\n", time.Now().Format(markerTimeFormat), state)
	}
	_ = os.Stdout.Sync()
}

// emitEventAck — EVENT_ACK|<event> (MODULE_API §2.8): «событие хоста ПОЛУЧЕНО».
//
// Нужно десктопному хосту: его канал (stdin) однонаправленный, и «байты записаны» приёма не
// доказывают — модуль, объявивший handoverMode:"signal" и не читающий stdin, молча остался бы без
// события, ПРИ ЭТОМ отменив себе cold-restart. Хост ждёт подтверждения до 2.5с. На Android приём
// доказывает возврат C-ABI-вызова, и лишняя строка там просто игнорируется — код один на обе.
//
// Имя обрезается по первому '|': payload `ACTION_RESULT|<id>|<token>` — секрет, и в
// helper.stdout.log попадать не должен.
func emitEventAck(event string) {
	name := event
	if i := strings.IndexByte(name, '|'); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	fmt.Printf("%s EVENT_ACK|%s\n", time.Now().Format(markerTimeFormat), name)
	_ = os.Stdout.Sync()
}

// ── События хоста: один обработчик на оба транспорта ──────────────────────────────────────────

var hostEventHandler func(string)

// setHostEventHandler — реакция МОДУЛЯ на событие хоста (сейчас единственное — "handover").
// Канон отвечает за транспорт и за EVENT_ACK; что делать с событием, решает модуль.
func setHostEventHandler(h func(string)) { hostEventHandler = h }

// handleHostEvent — ЕДИНАЯ точка входа событий хоста: desktop — строка stdin (канон
// shared/lifecycle::startHostEventReader), Android-слот — прямой C-ABI-вызов antinet_module_event
// (канон shared/entry). Форматы: `handover` и `ACTION_RESULT|<id>|<payload>`.
//
// EVENT_ACK печатается ПЕРВЫМ делом — подтверждаем ПОЛУЧЕНИЕ, а не завершение реакции: реакция
// бывает долгой (сброс пулов резолверов, переустановка сессии), а хост ждёт подтверждения секунды.
func handleHostEvent(event string) {
	event = strings.TrimSpace(event)
	emitEventAck(event)
	if strings.HasPrefix(event, "ACTION_RESULT|") {
		rest := event[len("ACTION_RESULT|"):]
		i := strings.IndexByte(rest, '|')
		if i < 0 {
			return
		}
		id, payload := rest[:i], strings.TrimSpace(rest[i+1:])
		actionWaitersMu.Lock()
		ch := actionWaiters[id]
		actionWaitersMu.Unlock()
		if ch != nil {
			select {
			case ch <- payload:
			default:
			}
		}
		return
	}
	if h := hostEventHandler; h != nil {
		h(event)
	}
}

// ── Интерактивные действия (MODULE_API §2.7) ──────────────────────────────────────────────────

var (
	actionWaitersMu sync.Mutex
	actionWaiters   = map[string]chan string{}
)

// runAction — ЕДИНЫЙ примитив интерактивного действия:
//  1. эмитит `ACTION_REQUIRED|<id>|<payloadB64>` в stdout (payload — ТИПИЗИРОВАННЫЙ JSON правила,
//     §2.7: {"type":"confirm|form|choice|display|webview", …}; UI рисует САМ AntiNet — модуль не
//     несёт ни строчки UI-кода);
//  2. БЛОКИРУЯСЬ ждёт результат — каналом (stdin/antinet_module_event) ИЛИ файлом-фоллбэком;
//  3. возвращает (декодированный JSON-ответ, false) либо ("", true) на отмену/таймаут.
//
// "CANCELLED" = юзер отменил / UI нет / истёк hard-cap хоста (~5 мин). Что это значит — решает
// МОДУЛЬ: на connect-пути обычно выйти, не записав маркер готовности; на живой сессии — не рвать её.
// `id` обязан быть уникальным на каждое действие.
func runAction(profileDir, id string, payload map[string]any) (string, bool) {
	pj, _ := json.Marshal(payload)
	fmt.Printf("ACTION_REQUIRED|%s|%s\n", id, base64.StdEncoding.EncodeToString(pj))
	_ = os.Stdout.Sync()

	s, timedOut := awaitActionResult(context.Background(), profileDir, id, actionDeadline)
	if timedOut || s == "CANCELLED" {
		return "", true
	}
	if dec, derr := base64.StdEncoding.DecodeString(s); derr == nil {
		return string(dec), false
	}
	return s, false // не-base64 — отдаём как есть (агностично)
}

// emitActionClose — ACTION_CLOSE|<id>: закрыть окно действия САМОМУ, не дожидаясь клика. Ради этого
// и существует тип `display` отдельно от `confirm` (device-code, push-подтверждение).
func emitActionClose(id string) {
	fmt.Printf("ACTION_CLOSE|%s\n", id)
	_ = os.Stdout.Sync()
}

// actionDeadline — потолок ожидания результата. Совпадает с hard-cap'ом хоста (~5 мин): ждать
// дольше бессмысленно (хост уже прислал бы "CANCELLED"), ждать меньше — отнимать у юзера время на
// капчу/логин.
const actionDeadline = 5 * time.Minute

// awaitActionResult — ждёт результат по каналу ИЛИ по файлу, что придёт первым. Второй возврат —
// «ждать больше нечего»: истёк дедлайн ЛИБО отменён ctx. Результат приходит КАНАЛОМ (он такой же
// секрет, как конфиг, §3); файл `<profileDir>/action_result.<id>` остаётся фоллбэком для старого хоста.
//
// `ctx` нужен модулю, у которого действие живёт внутри отменяемой сессии (qWDTT: капча в цепочке
// VK-auth — при разрыве сессии ждать её результат уже незачем). `runAction` выше передаёт
// `context.Background()`: у него отмену задаёт только дедлайн.
func awaitActionResult(ctx context.Context, profileDir, id string, timeout time.Duration) (string, bool) {
	ch := make(chan string, 1)
	actionWaitersMu.Lock()
	actionWaiters[id] = ch
	actionWaitersMu.Unlock()
	defer func() {
		actionWaitersMu.Lock()
		delete(actionWaiters, id)
		actionWaitersMu.Unlock()
	}()

	resultFile := filepath.Join(profileDir, "action_result."+id)
	deadline := time.After(timeout)
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case s := <-ch:
			return s, false
		case <-ctx.Done():
			return "", true
		case <-deadline:
			return "", true
		case <-tick.C:
			data, err := os.ReadFile(resultFile)
			if err != nil {
				continue
			}
			_ = os.Remove(resultFile)
			return strings.TrimSpace(string(data)), false
		}
	}
}
