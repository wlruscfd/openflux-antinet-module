# `shared/entry` — канон точек входа модуля (инжектируется build.py ВСЕГДА)

Две половины одной вещи: `entry_android.go` (`//go:build android`) и `entry_native.go`
(`//go:build !android`). `build.py` копирует нужную в main-пакет helper'а ПЕРЕД сборкой и удаляет
ПОСЛЕ. Гейта в `module.json` нет: точка входа нужна каждому.

## Зачем канон

Набор и сигнатуры C-ABI-экспортов — часть контракта, по которому слот-процесс находит модуль через
`dlsym`; порядок argv и перечень parse-only сабкоманд — часть контракта, по которому хост форкает
helper на десктопе. Разойтись с обоими можно молча: шим просто не найдёт символ, и увидишь ты это
на устройстве, а не на сборке.

## От модуля нужны РОВНО ДВЕ функции

```go
func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int
func moduleCall(verb, arg string) string
```

`realMain` блокирует, как `main()`, и возвращает код выхода. `moduleCall` обслуживает parse-only
сабкоманды §2.2 (`summarize` / `normalize` / `canping`) — они отрабатывают ДО любой тяжёлой
обвязки: ни lifecycle, ни сети, ни сокетов.

## Android: модуль — БИБЛИОТЕКА, а не процесс

Скачанный файл на Android запустить нельзя (W^X с API 29+ бьёт по `execve` любого writable-файла),
но `dlopen` под этот запрет не попадает. Поэтому сборка идёт `-buildmode=c-shared`, а слот AntiNet
грузит `.so` C-шимом и зовёт экспорты:

| Экспорт | Что делает |
|---|---|
| `antinet_module_run(configContent, resolversPath, profileDir, protectPath, listenFd)` | единственная обязательная точка входа (§2.3) → `realMain`. Конфиг приезжает СОДЕРЖИМЫМ, не путём; `listenFd` — готовый слушающий сокет, которым владеет хост (§2.6) |
| `antinet_module_event(event)` | событие хоста с ПРИЧИНОЙ (§2.8: `handover`/`netlost`/`netback`/`stall`, плюс `stop`/`ACTION_RESULT\|…`) → `handleHostEvent` (канон `shared/hostproto`) |
| `antinet_module_call(verb, arg)` | parse-only сабкоманды → `moduleCall`. Возврат — malloc'нутая C-строка |
| `antinet_module_free(p)` | парная освобождалка: память malloc'ена рантаймом ЭТОЙ `.so`, освобождать её обязан тот же аллокатор |

`main(){}` с пустым телом объявлен намеренно: `c-shared` требует его у `package main` (рантайм
ссылается на `runtime.main_main·f` при линковке), хотя НИКОГДА не вызывает.

⛔ **`SIGUSR1`-обработчик не заводи.** В слот-процессе доставка сигнала недетерминирована: ART
блокирует его на своих потоках, Go-потоки создаются от ART-потоков и наследуют маску, а
process-directed сигнал ядро отдаёт единственному незаблокированному потоку — ART'овскому «Signal»,
где Go форвардит его прежнему обработчику вместо `signal.Notify`. Прямой вызов через `dlsym` от
масок и версии ART не зависит.

## Desktop: обычный форкнутый процесс

```
helper <configPath> <resolversPath> <profileDir> <protectPath>
```

- `configPath` — ФОЛЛБЭК-путь: реальное содержимое приезжает в `ANTINET_MODULE_CONFIG` (§3, секреты
  мимо диска), читает его `readConfigForEntry` из `shared/hostproto`;
- `resolversPath` — доп. файл протокол-специфичного содержимого (модуль волен не использовать);
- `profileDir` — writable-каталог helper'а (маркер `ready`, логи, состояние);
- `protectPath` — UNIX-сокет protect-сервиса AntiNet (на десктопе не используется).

Слушающий сокет: номер fd в `ANTINET_LISTEN_FD`, если хост смог его передать (Unix). На Windows
передать сокет нечем — там приезжает только `LISTEN_PORT`, и `openListener` биндит сам.

**Править ТОЛЬКО здесь.** Копии в `native/<module>/` (если появятся в рабочем дереве после
прерванной сборки) — артефакт инъекции: build.py удаляет их в `finally`.
