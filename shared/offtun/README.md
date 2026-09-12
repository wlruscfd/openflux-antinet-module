# shared/offtun — канонический off-TUN socket-protect модулей (инжектируется build.py)

**Единый источник** off-TUN-привязки сокетов helper'а к ФИЗИЧЕСКОМУ интерфейсу для ВСЕХ desktop-модулей
(Linux `SO_BINDTODEVICE` / Windows `IP_UNICAST_IF` / macOS `IP_BOUND_IF`). Логика детекта интерфейса и
setsockopt у всех модулей одна и та же — и адаптер под protect-хук data-plane библиотеки тоже:
`offtun_adapter.go` держит десктопную половину обеих форм (`dialControl`, `protectFdFunc`), android-
половина с теми же именами живёт в [`shared/protect`](../protect/README.md). У модуля не остаётся ничего.

## Зачем off-TUN

helper форкается root-backend'ом и наследует его положение в TUN; под `auto_route` его egress по
умолчанию идёт В TUN. sing-box `process_name→direct` НЕ спасает резолвер-UDP (StormDNS на :53):
route-правило `port:53→hijack-dns` стоит ПЕРЕД per-app bypass → DNS перехватывается ДО bypass. Плюс для
эфемерных UDP-сокетов process-attribution sing-box ненадёжна. `SO_BINDTODEVICE`/`IP_UNICAST_IF`/
`IP_BOUND_IF` уводят сокет на физ-iface МИМО TUN и ВСЕХ route-правил. Мирор Android SCM_RIGHTS-protect
(тот же off-TUN-инвариант, иной механизм).

## Как это работает (build.py-инъекция, MODULE_API §4)

- Гейта в `module.json` нет: канон инжектится **ВСЕГДА**, потому что десктопная половина
  protect-адаптера нужна каждому модулю.
- `build.py` при desktop-сборке (`build_desktop`) КОПИРУЕТ `offtun_*.go` в main-пакет helper'а модуля
  (`<goDir>/<goPkg>`), запускает `go build`, затем УДАЛЯЕТ копии в `finally`. Поэтому в дереве модуля
  их нет и класть туда не надо: канон живёт и трекается только здесь.
- Модуль зовёт **`dialControl(protectPath, *protectStat)`** либо **`protectFdFunc(protectPath)`** —
  те же имена, что на Android, поэтому build-тегов у модуля нет вовсе. Под капотом на десктопе они
  отдают:
  - **`offtunBindControl(network, address, syscall.RawConn) error`** — форма `net.Dialer.Control` /
    `net.ListenConfig.Control`.
  - **`offtunBindFd(fd int) bool`** — форма `func(fd) bool` (masterdns `nativeclient.Options.Protect`).
  Обе формы определены во всех `offtun_*.go` (неиспользуемая — просто unused package-level func, Go
  это допускает).
- На android `offtun_*` НЕ инжектируются (build_android отдельный путь) — там те же `dialControl`/
  `protectFdFunc` приезжают из `shared/protect/protect_adapter_android.go` и идут через SCM_RIGHTS.

## Требование к модулю

`go.mod` модуля должен иметь `golang.org/x/sys` (Windows/Darwin-формы импортят `golang.org/x/sys/{windows,unix}`).

## Файлы

| Файл | build-tag | Содержит |
|---|---|---|
| `offtun_adapter.go` | `!android` | десктопная половина protect-адаптера: `dialControl`, `protectFdFunc` (те же имена, что у android-половины в `shared/protect`) |
| `offtun_linux.go` | `linux && !android` | `physicalDefaultIface` + обе формы (SO_BINDTODEVICE) |
| `offtun_windows.go` | `windows` | обе формы (IP_UNICAST_IF, htonl) |
| `offtun_darwin.go` | `darwin` | обе формы (IP_BOUND_IF) |
| `offtun_physiface.go` | `darwin` | `physicalIfaceIndex` для macOS (NIC-перебор). ⚠ **НЕ общий с Windows**: у Windows свой `physicalIfaceIndex` в `offtun_windows.go` по таблице маршрутов (`GetIpForwardTable`) — NIC-перебор на multi-NIC Windows выбирал виртуальный адаптер |
| `offtun_other.go` | прочее !android | no-op обе формы |

**Править ТОЛЬКО здесь.** Копии в `native/<module>/` (если появятся в рабочем дереве после сборки) —
артефакт инъекции, не редактировать.
