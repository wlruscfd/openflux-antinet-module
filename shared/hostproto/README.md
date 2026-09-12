# `shared/hostproto` — канон протокола разговора с хостом (инжектируется build.py ВСЕГДА)

Один файл: `hostproto.go` (`package main`, БЕЗ build-тега — платформенного здесь ничего нет).
`build.py` копирует его в main-пакет helper'а ПЕРЕД сборкой и удаляет ПОСЛЕ: в дереве модуля его
нет и быть не должно. Гейта в `module.json` у канона нет — без него не работает ни один модуль.

## Зачем канон

Это не «утилитки», а сам контракт: формат конфига, владение слушающим сокетом, перечень
stdout-маркеров, порядок `EVENT_ACK`. Копия расходится с контрактом МОЛЧА — сборка проходит, а хост
перестаёт понимать модуль. До сведения одно и то же жило тремя копиями под тремя именами: echo
`readConfigForEntry` / qWDTT `readModuleConfigContent` / masterdns `readModuleConfigContent`; три
`handleHostEvent`; два `openListener` плюс qWDTT'шная пара `listen_other.go`/`listen_windows.go`.

## Что даёт

| Символ | Что делает |
|---|---|
| `readConfigForEntry(path) string` | СОДЕРЖИМОЕ конфига в desktop-форме доставки: сначала `ANTINET_MODULE_CONFIG` (base64), файл по argv-пути — только фоллбэк для старого хоста (§3: секреты мимо диска) |
| `parseConfig(content) map[string]string` | разбор KEY=VALUE-текста (`#` — комментарий). Формат ЕДИН на обеих платформах и для обеих форм доставки |
| `openListener(port, listenFd) (net.Listener, error)` | усыновление переданного хостом fd (`net.FileListener`), либо bind по `LISTEN_PORT`, если fd передать было нечем (Windows / старый хост) |
| `emitProgress(format, args…)` | `PROGRESS\|<текст>` — transient-тост ТОЛЬКО на connect-пути; подряд идущий одинаковый текст гасится |
| `emitLog(format, args…)` | `LOG\|<текст>` — постоянная запись в визуальном логе AntiNet |
| `emitStatus(state, detail)` + `statusOK`/`statusWaiting`/`statusDegraded`/`statusFatal` | `STATUS\|<state>[\|<detail>]` — типизированное состояние helper'а; повтор ТОГО ЖЕ состояния не печатается (§2.13 требует дедуп на стороне модуля) |
| `emitEventAck(event)` | `EVENT_ACK\|<event>` — «событие получено»; имя обрезается по первому `\|`, чтобы секрет из `ACTION_RESULT` не попал в `helper.stdout.log` |
| `setHostEventHandler(func(string))` | регистрация РЕАКЦИИ модуля на событие хоста (канон отвечает только за транспорт и ack) |
| `handleHostEvent(event)` | единая точка входа событий: desktop — строка stdin (`shared/lifecycle::startHostEventReader`), Android — C-ABI `antinet_module_event` (`shared/entry`) |
| `runAction(profileDir, id, payload) (string, bool)` | интерактивное действие целиком: `ACTION_REQUIRED\|<id>\|<payloadB64>` → блокирующее ожидание → декодированный ответ либо `("", true)` на отмену/таймаут. UI рисует САМ AntiNet — модуль не несёт ни строчки UI-кода |
| `awaitActionResult(ctx, profileDir, id, timeout) (string, bool)` | то же ожидание отдельно, с СВОИМ `ctx` — для действия внутри отменяемой сессии (qWDTT: капча в цепочке VK-auth) |
| `emitActionClose(id)` | `ACTION_CLOSE\|<id>` — закрыть окно действия самому, не дожидаясь клика (тип `display`: device-code, push-подтверждение) |

## Что требуется от модуля

Ничего, кроме двух функций, которые зовёт канон [`shared/entry`](../entry/README.md): `realMain` и
`moduleCall`.

⚠ **Имя `parseConfig` занято каноном.** Свой разбор в СВОЙ формат называй иначе — у masterdns это
`parseStormDnsConfig`, у qWDTT `parseHelperConfig`. Коллизия имён в одном `package main` — ошибка
сборки `redeclared`, и словишь ты её только при первом же билде после инъекции.

⚠ **Граница локализации проходит по ПРИЁМНИКУ, а не по маркеру** (§2.9). Текст ПОСЛЕ тега в
`PROGRESS|`/`LOG|` юзер видит тостом и на экране «Логи» — он ОБЯЗАН выбираться по `APP_LANG`
(эталоны: `demoStringsFor` у echo, `mdStringsFor` у masterdns, `qwdttStringsFor` у qWDTT). А сами
ТЕГИ, таймстамп-префикс, `detail` у `STATUS|` и весь `log.Printf` — ASCII/английский ВСЕГДА: первые
разбирает хост, вторые читает разработчик грепом по `helper.stdout.log`, а grep-тулинг ломается на
не-ASCII.

⛔ **Усыновление слушающего сокета ОДНОРАЗОВОЕ.** `os.NewFile` забирает владение дескриптором,
`net.FileListener` его дуплицирует, оригинал закрывается — второй `openListener` на то же ЧИСЛО
обречён на `invalid argument`. Держи `net.Listener` в переменной уровня процесса и НЕ закрывай его
при внутренних перезапусках сессии.

**Править ТОЛЬКО здесь.** Копия в `native/<module>/` (если появится в рабочем дереве после
прерванной сборки) — артефакт инъекции: build.py удаляет её в `finally`.
