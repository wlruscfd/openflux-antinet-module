# shared/lifecycle — канон примитивов жизненного цикла helper'а (инжектируется build.py всегда)

**Единый источник** четырёх вещей, которые нужны любому модулю и не содержат ни строчки модульной
специфики. Гейта в `module.json` у канона нет — он приезжает всем.

| функция | android | !android (десктоп) |
|---|---|---|
| `dieWithParent()` | `unix.Prctl(PR_SET_PDEATHSIG, SIGKILL)` — но родитель слот-процесса zygote, он не умирает: вызов безвреден и орфана не ловит; реальная защита на Android — самореап слота в `ModuleHostService.onDestroy` | **linux**: тот же `PR_SET_PDEATHSIG` — helper форкнутый ребёнок бэкенда, сигнал приходит в момент смерти родителя. **windows/darwin**: no-op, аналога нет → сироту ловит только стартовый свип хоста `CleanupOrphanHelpers` |
| `protectFromOomKill()` | `/proc/self/oom_score_adj = -1000`, defense-in-depth к хостовому `BIND_IMPORTANT` | no-op: модели LMK/vendor-killer нет |
| `startHostEventReader()` | no-op: модуль — библиотека в слот-процессе, хост зовёт `antinet_module_event` (экспорт канона `shared/entry`) | построчный `stdin` → `handleHostEvent` (канон `shared/hostproto`): **единственный** канал событий хоста (причина сетевого события — `handover`/`netlost`/`netback`/`stall` по `hostEvents` §2.8, плюс `stop` и `ACTION_RESULT\|…`) |
| `writeReady(dir, port)` | маркер готовности `ready` + `socks.port`, атомарно (`.tmp` → rename); ошибка записи `ready` возвращается вызывающему | то же самое |

⛔ **Обработчик `SIGUSR1` не заводи.** Сигналов не шлёт ни один хост: на Android доставка в
слот-процессе под ART недетерминирована (хост зовёт C-ABI-экспорт), на десктопе хост пишет строку
в stdin. Обработчик будет мёртвым кодом на обеих платформах.

## Почему канон, а не по копии в модуле

Это чистая обвязка ОС, одинаковая для всех: копии тут не расходятся «если не следить» — они
расходятся всегда, потому что каждый модуль правит свою по своему поводу. Расхождение при этом не
ломает сборку и обнаруживается только в рантайме: тихий однострочник против варианта, печатающего
две диагностические строки в stderr на каждом старте; один и тот же stdin-читатель под тремя
разными именами файлов в трёх модулях. Канон снимает вопрос целиком.

## Что канон не забирает

**Реакция на событие — модульная.** Этот канон отвечает только за транспорт: прочитать строку из
stdin и отдать её в `handleHostEvent` (канон [`shared/hostproto`](../hostproto/README.md), он же
печатает `EVENT_ACK`). Что делать с событием, решает модуль — регистрирует свой обработчик
`setHostEventHandler(func(string))` (у echo — демо-лог, у qWDTT — re-spawn TURN/DTLS, у masterdns —
flush резолверных пулов + session restart).

⚠ **Protect-адаптер канону lifecycle не принадлежит, но и в модуле его тоже нет.** Форм у него две,
и обе канонные, под одними именами на обеих платформах: `dialControl` (форма `net.Dialer.Control`) и
`protectFdFunc` (форма `func(fd int32) bool`) — см. [`shared/protect`](../protect/README.md)
(android) и [`shared/offtun`](../offtun/README.md) (десктоп).

## Требование к модулю

`go.mod` должен содержать `golang.org/x/sys` — android-половина канона зовёт `unix.Prctl`.

## Файлы

| Файл | build-tag | Содержит |
|---|---|---|
| `lifecycle_android.go` | `android` | `protectFromOomKill`, `startHostEventReader` (no-op) |
| `lifecycle_other.go` | `!android` | их десктопные версии: no-op OOM + реальный stdin-читатель |
| `lifecycle_dieparent_linux.go` | `linux && !android` | `dieWithParent` через `PR_SET_PDEATHSIG` |
| `lifecycle_dieparent_nonlinux.go` | `!(linux && !android)` | `dieWithParent` — no-op |
| `lifecycle_ready.go` | — | `writeReady`, платформенного в ней ничего нет |

⚠ Тег `linux && !android` у `dieWithParent` обязателен: `GOOS=android` удовлетворяет и голому
тегу `linux`, поэтому без `!android` файл попал бы в android-сборку и дал `redeclared`.

**Править только здесь.** Копии в `native/<module>/` (если появятся в рабочем дереве после
прерванной сборки) — артефакт инъекции: build.py удаляет их в `finally`.
