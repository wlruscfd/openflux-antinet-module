# Модуль «OpenFlux» для AntiNet (`openflux://`)

Самодостаточный архив протокол-модуля AntiNet: исходники модуля + кросс-платформенная сборочная
система + документация. Собирается под **Android + Windows/Linux/macOS** без репозитория AntiNet.

Домашняя страница протокола: https://github.com/p1neappleXpress/OpenFlux

## Что внутри

| Путь | Что это |
|---|---|
| `README.md` | этот файл — точка входа |
| _(доков системы здесь нет)_ | `MODULE_API.md` / `MODULE_SYSTEM.md` / `PORTING.md` в этот архив не входят: он — авторская поставка модуля, а не SDK. Ссылки на них ниже ведут в эталонный архив `echo-module` и в репозиторий AntiNet |
| `build.py` | сборщик helper-бинарей под все ОС. `python build.py --help`, `--doctor` |
| `tools/build-module.py` | низкоуровневый Android-билдер (NDK clang → `.so`), зовётся из `build.py` |
| `examples/moduleopenflux/` | **сам модуль-образец**: `module.json` (ЕДИНЫЙ дескриптор) + `native/` (Go data-plane) |
| `shared/` | **каноны** — общий код всех модулей. `build.py` копирует их в main-пакет helper'а ПЕРЕД сборкой и убирает после; в дереве модуля их нет и класть туда не надо |
| `antinet-module.example.json` | образец манифеста авто-обновления (реальный генерит `--bundle`) |
| `LICENSE` | лицензия сборочной системы и канонов — **MIT**. Лицензия САМОГО модуля — `GPL-3.0-or-later`, см. ниже |

## Лицензия

⚠ Лицензий в архиве ДВЕ, и это не формальность.

- **Сборочная система и каноны** (`build.py`, `tools/`, `shared/`, доки) — **MIT**
  (`LICENSE` в корне архива).
- **Сам модуль** `examples/moduleopenflux/` — **GPL-3.0-or-later** (`examples/moduleopenflux/LICENSE`).

MIT совместим с GPL-3.0-or-later в одну сторону: собранный из этого архива модуль распространяется
на условиях GPL-3.0-or-later. Если делаешь свой модуль на базе канонов — на ТВОЙ код
распространяется MIT, и копилефт этого модуля тебя не касается: бери за образец echo,
а не этот модуль, если не хочешь наследовать GPL-3.0-or-later.

Каноны — отдельный случай: `build.py` копирует `shared/*` в main-пакет твоего helper'а перед
сборкой, то есть этот код физически попадает в твой бинарь. Он MIT намеренно — копилефта в нём нет,
и твоему модулю он ничего не навязывает. Поэтому `SPDX-License-Identifier` стоит в шапке каждого
канона: инжектированный файл уезжает в твоё дерево, и маркер обязан ехать вместе с ним.

### Каноны `shared/` — что инжектируется и когда

| Канон | Когда | Что даёт |
|---|---|---|
| `shared/lifecycle/` | **всегда** | `dieWithParent` (PDEATHSIG), `protectFromOomKill`, `startHostEventReader` (события хоста), `writeReady` (маркер готовности) |
| `shared/protect/` | **всегда** | `protectViaService` — SCM_RIGHTS-клиент protect-сервиса AntiNet (Android) |
| `shared/socks5/` | `"socks5": true` | **весь SOCKS5-протокол**: рукопожатие, user/pass, разбор запроса, accept-петля, реле, UDP ASSOCIATE. Твоё дело — только транспорт |
| `shared/offtun/` | **всегда** (гейта нет), но только в desktop-сборку | off-TUN bind сокета к физ-интерфейсу на desktop + десктопная половина protect-адаптеров (`dialControl`/`protectFdFunc`) |
| `shared/hostproto/` | **всегда** | весь протокол разговора с хостом: разбор конфига, усыновление слушающего сокета, маркеры stdout, события хоста, интерактивные действия |
| `shared/entry/` | **всегда** | точки входа: C-ABI-экспорты на Android, argv-разбор на десктопе. Тебе остаётся `realMain` + `moduleCall` |
| `shared/dns/` | `"dnsResolver": true` | protected off-tunnel резолв твоих dial-таргетов (`newProtectedResolver`/`LookupHost`): TTL-кэш + single-flight + прямой UDP-запрос к `DNS_SERVERS` через твой же `dialControl` |

## Свой модуль — папкой РЯДОМ с образцом

`build.py` находит модули сам, сканируя `examples/*/module.json`. Никакого реестра править не надо:

```
cp -r examples/moduleopenflux examples/modulemymod     # рядом, а не поверх
# → отредактировать examples/modulemymod/module.json: schemes / name / version /
#   helperBinary{android:"libmymod.so", desktop:"mymod-helper"} / build{goDir,goPkg}
python build.py --module mymod --os all             # ключ = имя папки без префикса "module"
```

Образец `moduleopenflux` при этом остаётся на месте — есть с чем сверяться.

## Требования (и как поставить)

Проверить хост одной командой:

```
python build.py --doctor --os all --module openflux
```

Он печатает, что найдено, чего нет и КОМАНДУ установки под твою ОС. Коротко — три РАЗНЫХ
требования, и путать их не надо:

| Что собираем | Чем | Кросс-компиляция |
|---|---|---|
| desktop-helper (`windows`/`linux`/`darwin`) | **только Go 1.26+** (эту версию требует `go.mod` модуля; с go1.21 Go догружает нужный тулчейн сам) | **да, с любого хоста на любую ОС** (`CGO_ENABLED=0`, C-тулчейн не нужен) |
| android-helper (`.so`, `c-shared`) | Go + **Android NDK** | **да, с любого хоста** |

⛔ **C-компилятор модулю не нужен, и UI ты не пишешь.** Интерактивные действия (капча/логин/2FA)
рисует КЛИЕНТ: модуль эмитит строку `ACTION_REQUIRED|<id>|<payloadB64>` с декларативным правилом,
а рендерер принадлежит хосту — Android `ModuleActionActivity`, Desktop `antinet-action` (идёт
вместе с клиентом, форкается для любого модуля). Легаси-поле `module.json: actionBinary`
объявлять НЕ надо: на Android оно вообще не читается, на Desktop хостовый рендерер всегда
пробуется первым. Подробно — `MODULE_SYSTEM.md` § «C-тулчейн модулю НЕ нужен».

Плюс Python 3 для самого `build.py`. **Android SDK / Gradle / AGP НЕ нужны** ни для чего: модуль —
файл, а не приложение. На Android он поставляется скачиваемой `.so` (`-buildmode=c-shared`),
которую AntiNet грузит `dlopen`'ом в свой зарезервированный слот-процесс.

Подробные команды установки Go / NDK / C-тулчейна под Windows, Linux и macOS — `MODULE_SYSTEM.md`
§ «Тулчейн».

## 1. Сборка helper'ов (все платформы)
```
python build.py --module openflux --os all        # Android .so + Windows/Linux/macOS helper
python build.py --module openflux --os linux       # только Linux (хост-арх; --arch для другой)
python build.py --module openflux --os android      # только Android .so
python build.py --module openflux --os android --abis arm64-v8a,armeabi-v7a,x86_64
```
Результат — самодостаточный каталог на каждую цель (артефакт + `module.json`):
`examples/moduleopenflux/dist/desktop/<os>_<arch>/` и `examples/moduleopenflux/dist/android/<abi>/`.

## 2. Где править протокол
`examples/moduleopenflux/native/.../main.go` (+ соседние .go) — это data-plane helper'а. **ОСТАВЬ как есть**
обязательную обвязку: SOCKS5-фронт на переданном хостом сокете, маркер готовности `ready`,
protect-fd сокетов, сабкоманды `summarize`/`normalize` (контракт — `MODULE_API.md` §2.3).

## 3. Публикация (чтобы AntiNet ставил по `antinet://`-ссылке и авто-обновлял)
1. **СНАЧАЛА дескриптор, потом сборка.** В `module.json`: `updateUrl` = адрес, по которому БУДЕТ
   лежать манифест, и поднятая `version`. Порядок именно такой, потому что `module.json` едет ВНУТРИ
   каждого бандла: адрес, вписанный после сборки, до пользователей не доедет — у них не будет ни
   авто-проверки, ни рабочего «Поделиться модулем» (ссылка уйдёт без `m`, и получателю ставить
   неоткуда). Правишь `updateUrl` позже — пересобирай и ПЕРЕЗАЛИВАЙ бандлы.
   ⚠ Адрес манифеста обязан быть СТАБИЛЬНЫМ (файл на ветке, напр.
   `raw.githubusercontent.com/<owner>/<repo>/main/antinet-module.json`), его перезаписывают на каждый
   релиз. Release-ассет для манифеста не годится: у каждого релиза он свой, и запечённый в дескриптор
   адрес навсегда останется на старой версии. Сами ZIP'ы, наоборот, могут переезжать свободно.
2. Собери релиз-артефакты:
   ```
   python build.py --module openflux --os all      # helper'ы под все цели → dist/
   python build.py --bundle --module openflux      # → dist-release/*.zip + antinet-module.json
   ```
3. Залей на хостинг (напр. GitHub Releases) каждый `dist-release/*.zip`.
4. Открой `dist-release/antinet-module.json`, впиши реальные URL'ы бандлов (`android[<abi>]` +
   `desktop[<os>_<arch>]` — ВСЕ, что собрал: манифест без бандла под ABI устройства эта платформа
   отвергает целиком) и залей его по адресу из шага 1.
5. Следующий релиз — снова с шага 1: без поднятой `version` авто-проверка обновления не увидит.
   Сравнение посегментно-числовое, так что «1.3.10» корректно новее «1.3.7».
6. Распространяй install-ссылку (один тап «скачать+поставить») — её собирает сам AntiNet
   («Настройки → Модули → Поделиться модулем»), руками формат готовить не надо:
   `antinet://import?module=<base64url-no-pad JSON>`, где JSON =
   `{"s":"openflux","n":"OpenFlux","m":"<updateUrl>","h":"https://github.com/p1neappleXpress/OpenFlux"}`. Ключ `m` и есть
   `updateUrl`; без него получатель установить не сможет — диалог лишь предложит открыть `h`.

Полная спецификация публикации/авто-обновления/ссылки — **`MODULE_API.md` §2.5**.

## Контракт (кратко)
Helper ОБЯЗАН: обслуживать SOCKS5 на сокете, который дал хост; писать маркер `ready`; защищать
исходящие сокеты protect-fd; отвечать на `<helper> summarize <link>` (имя+сервер) и
`<helper> normalize <raw>`. Опции (хендовер `handoverMode`, off-TUN, интерактив-действия, настройки,
тайминги, контракт восстановления) — `MODULE_API.md`.
