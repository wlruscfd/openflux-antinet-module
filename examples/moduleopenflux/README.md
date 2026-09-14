# moduleopenflux — модуль OpenFlux (TCP-туннель поверх мессенджеров)

> Порт клиентской половины [OpenFlux](https://github.com/p1neappleXpress/OpenFlux) (GPL-3.0) в
> companion-модуль AntiNet. Контракт модулей — `../../MODULE_API.md`; раскладка зон — `../../README.md`.

Трафик уходит не по своему сетевому протоколу, а **сообщениями внутри мессенджера**: позицией
курсора в документе Яндекс.Документов либо сигнальным каналом звонка MAX. Снаружи это выглядит как
работа в облачном редакторе или звонок, а не как VPN. На той стороне нужен **свой exit-node
OpenFlux** — модуль это только клиент.

```
sing-box → SOCKS5 → gVisor netstack → сырые IPv4-пакеты → транспорт мессенджера → exit-node
```

## Ссылка

```
openflux://yandex?url=<urlencoded адрес документа>[#Имя]                    — апстрим
openflux://oneme?token=<токен MAX>&uid=<id собеседника>[#Имя]                — апстрим
openflux://import?data=<base64url-JSON без паддинга>                        — форк openflux-server
```

Схема ОДНА, транспорт — первый сегмент: `yandex://`/`oneme://` слишком общие имена, чтобы занимать
их в реестре схем хоста. Имена параметров взяты один в один из флагов апстримного CLI
(`-transport`/`-url`/`-maxToken`/`-maxUid`) — своего формата ссылки у апстрима нет вовсе, он
настраивается аргументами командной строки.

Третья форма (`import`) — ссылка, которую выдаёт controlplane форка
[openflux-server](https://github.com/wlruscfd/openflux-server) на созданный ключ (админ-панель /
Android-приложение форка, кнопка «Поделиться профилем»). `data=` — тот же JSON, что и в
`buildDeepLink` форка: `{"name","mode":"key","control_url","key_token","doc_url","transport"}`.
`doc_url`/`transport` читаются прямо из ссылки — модуль НЕ ходит на `control_url` за ними (см.
`decodeImportLink` в `main.go`), ровно как и Android-приложение форка не ходит. `transport: "volga"`
распознаётся, но пока возвращает явную ошибку — сам транспорт (`transport/yandex/volga.go` форка,
~1000 строк) в этот модуль ещё не портирован.

## Раскладка

| Файл / каталог | Зона |
|---|---|
| **`module.json`** | дескриптор: схема `openflux`, `socks5`+`dnsResolver` (каноны), `handoverMode: signal` + `hostEvents: [handover, netlost, netback, stall]` (§2.8 — модуль разбирает все четыре причины), `pingTimeoutSec: 60`, три настройки (`dialTimeoutSec`/`keepAliveSec`/`debugLog`) |
| **`native/openflux/cmd/helper/main.go`** | **единственный файл, который принадлежит модулю**: грамматика ссылки, `realMain`, `moduleCall`, SOCKS5-транспорт поверх туннеля, protected-резолвер dial-таргетов |
| `native/openflux/transport/`, `network/`, `utils/`, `tunnel/endpoint.go` | **дословные копии [openflux-server](https://github.com/wlruscfd/openflux-server)** — побайтово, включая авторские комментарии. Бамп = перезапись файлов, сверка `diff --strip-trailing-cr` |
| `native/openflux/transport/*/handover.go` | НАШИ файлы рядом с вендорными: `Handover()` каждого транспорта (событие хоста §2.8). Отдельным файлом именно чтобы вендорные оставались перезаписываемыми |
| `native/openflux/transport/yandex/mapkeys.go` | НАШ файл: `mapKeys` дословно из `volga.go` форка — сам транспорт Volga не портирован, а диагностика `fetchDocInfo` функцию зовёт |
| `native/openflux/tunnel/tunnel.go` | переписан client-only (gVisor-стек вместо системного TUN, `DialTCP` с дедлайном из ctx, серверная половина убрана) |
| `dist/` | билды. Gitignored |

**Платформенного кода и build-тегов у модуля нет ни одного.** Точки входа (`shared/entry`),
разговор с хостом (`shared/hostproto`), жизненный цикл (`shared/lifecycle`), protect/off-TUN
(`shared/protect` + `shared/offtun`), SOCKS5 (`shared/socks5`) и резолвер (`shared/dns`) —
каноны, которые `build.py` инжектит перед сборкой и удаляет после.

## Откуда берётся вендорный код

Источник — **[openflux-server](https://github.com/wlruscfd/openflux-server)**, форк апстрима, а не
сам [апстрим](https://github.com/p1neappleXpress/OpenFlux): форк несёт найденные вживую фиксы
транспорта Yandex Docs, которых в апстриме нет (engine.io/socket.io-рукопожатие перед отправкой
чего-либо в сокет, read-deadline из серверных `pingInterval`/`pingTimeout`, обрыв сокета на провале
keep-alive, отсечка собственного эха, рабочий экспоненциальный backoff, безопасный разбор
`client-config`, браузерный набор заголовков, гонка и `recover` в `InjectInbound`).

**Эти файлы копируются побайтово, включая авторские комментарии.** Бамп = перезапись файлов из
форка и `diff --strip-trailing-cr` для проверки, что расхождений не осталось. Свои комментарии
и правки внутрь вендорных файлов не вносятся — всё модульное живёт в отдельных файлах рядом
(`handover.go`, `mapkeys.go`, `cmd/helper/main.go`).

### Единственные расхождения с форком

| Где | Что и почему |
|---|---|
| `cmd/helper/main.go` | НАШ файл целиком: грамматика ссылки, `realMain`/`moduleCall`, SOCKS5 поверх туннеля. Он же связывает вендорный код с платформой — `transport.SetProtector(protectFdFunc(...))` и подмена `net.DefaultResolver` (Husi-pattern: UID helper'а ВКЛЮЧЁН в TUN, поэтому незащищённый сокет транспорта ушёл бы в туннель, который транспорт сам же и поднимает). Серверы DNS берутся от хоста, а не из вендорного хардкода |
| `transport/yandex/handover.go`, `transport/oneme/handover.go` | НАШИ: `Handover()` — реакция на события хоста (§2.8), у форка такого понятия нет. В вендорный интерфейс `transport.Transport` метод НЕ добавлен (иначе `transport.go` перестал бы быть копией) — helper держит ссылку на сам транспорт |
| `transport/yandex/mapkeys.go` | НАША выноска: `mapKeys` дословно из `volga.go`, который не портирован |
| `tunnel/tunnel.go` | переписан client-only: вендорный несёт обе стороны и поднимает системный TUN, модулю он не положен (трафик уходит хосту через SOCKS5). Плюс дедлайн дозвона из `ctx` — сам gVisor не сдаётся никогда — и запрет нелитеральных адресов: резолв обязан произойти ДО туннеля |
| `transport/oneme/max_wclient.go` | ⚠ 10 строк: убран дамп контактов аккаунта MAX (имена, телефоны) в stdout. У модуля stdout — это `helper.stdout.log`, который целиком уезжает в баг-репорты |

Транспорт `volga` (собственный транспорт форка, `transport/yandex/volga.go`, ~1000 строк) и его
`browser_ua.go`-зависимости в модуль не портированы.

Транспорт `volga` (собственный транспорт форка, `transport/yandex/volga.go`, ~1000 строк) в этот
модуль **не портирован** — `decodeImportLink` распознаёт `transport: "volga"` в ссылке и явно
отказывает, а не падает и не молча использует не тот транспорт.

## Сборка

```bash
python build.py --os android --module openflux --abis arm64-v8a   # .so (c-shared)
python build.py --os linux   --module openflux                    # desktop
python build.py --os all     --module openflux -y                 # всё сразу
```

`-ldflags=-checklinkname=0` прописан в `module.json` (`build.ldflags`) и подставляется сам.

## Известные ограничения

- **Только TCP.** UDP/QUIC через этот туннель не ходят — значит, UDP-протоколы (hysteria2, tuic,
  wireguard) каскадом за OpenFlux не работают.
- **Нужен свой exit-node.** Публичных нет; ссылка без работающей той стороны подключится «в никуда».
- **Хендовер — `restart`.** Сессия мессенджера привязана к соединению, поднятому на старой сети;
  in-place переустановить её нечем, поэтому при смене сети хост перезапускает helper целиком.
