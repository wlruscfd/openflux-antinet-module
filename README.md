# Модуль «OpenFlux» для AntiNet (`openflux://`)

Самодостаточный архив протокол-модуля AntiNet: исходники модуля + кросс-платформенная сборочная
система + документация. Собирается под **Android + Windows/Linux/macOS** без репозитория AntiNet.

Домашняя страница протокола: https://github.com/p1neappleXpress/OpenFlux

## Что внутри

| Путь | Что это |
|---|---|
| `README.md` | этот файл — точка входа |
| `UPGRADE.md` | **бамп апстрима одной командой** — как влить новую версию своего апстрима трёхсторонним слиянием, не потеряв интеграционный слой |
| _(остальных доков системы здесь нет)_ | `MODULE_API.md` / `MODULE_SYSTEM.md` / `PORTING.md` в этот архив не входят: он — авторская поставка модуля, а не SDK. Ссылки на них ниже ведут в эталонный архив `echo-module` и в репозиторий AntiNet |
| `build.py` | сборщик helper-бинарей под все ОС. `python build.py --help`, `--doctor` |
| `tools/build-module.py` | низкоуровневый Android-билдер (NDK clang → `.so`), зовётся из `build.py` |
| `examples/moduleopenflux/` | **сам модуль-образец**: `module.json` (единый дескриптор) + `native/` (Go data-plane) |
| `shared/` | **каноны** — общий код всех модулей. `build.py` копирует их в main-пакет helper'а перед сборкой и убирает после; в дереве модуля их нет и класть туда не надо |
| `antinet-module.example.json` | образец манифеста авто-обновления (реальный генерит `--bundle`) |
| `LICENSE` | лицензия сборочной системы и канонов — **MIT**. Лицензия самого модуля — `GPL-3.0-or-later`, см. ниже |

## Лицензия

⚠ Лицензий в архиве две, и это не формальность.

- **Сборочная система и каноны** (`build.py`, `tools/`, `shared/`, доки) — **MIT**
  (`LICENSE` в корне архива).
- **Сам модуль** `examples/moduleopenflux/` — **GPL-3.0-or-later** (`examples/moduleopenflux/LICENSE`).

MIT совместим с GPL-3.0-or-later в одну сторону: собранный из этого архива модуль распространяется
на условиях GPL-3.0-or-later. Если вы делаете свой модуль на базе канонов, на ваш код
распространяется MIT, и копилефт этого модуля вас не касается: берите за образец echo,
а не этот модуль, если не хотите наследовать GPL-3.0-or-later.

Каноны — отдельный случай: `build.py` копирует `shared/*` в main-пакет вашего helper'а перед
сборкой, то есть этот код физически попадает в ваш бинарь. Он MIT намеренно — копилефта в нём нет,
и вашему модулю он ничего не навязывает. Поэтому `SPDX-License-Identifier` стоит в шапке каждого
канона: инжектированный файл уезжает в ваше дерево, и маркер обязан ехать вместе с ним.

### Каноны `shared/` — что инжектируется и когда

| Канон | Когда | Что даёт |
|---|---|---|
| `shared/lifecycle/` | **всегда** | `dieWithParent` (PDEATHSIG), `protectFromOomKill`, `startHostEventReader` (события хоста), `writeReady` (маркер готовности) |
| `shared/protect/` | **всегда** | `protectViaService` — SCM_RIGHTS-клиент protect-сервиса AntiNet (Android) |
| `shared/socks5/` | `"socks5": true` | **весь SOCKS5-протокол**: рукопожатие, user/pass, разбор запроса, accept-петля, реле, UDP ASSOCIATE. Ваше дело — только транспорт |
| `shared/offtun/` | **всегда** (гейта нет), но только в desktop-сборку | off-TUN bind сокета к физ-интерфейсу на desktop + десктопная половина protect-адаптеров (`dialControl`/`protectFdFunc`) |
| `shared/hostproto/` | **всегда** | весь протокол разговора с хостом: разбор конфига, усыновление слушающего сокета, маркеры stdout, события хоста, интерактивные действия |
| `shared/entry/` | **всегда** | точки входа: C-ABI-экспорты на Android, argv-разбор на десктопе. Вам остаётся `realMain` и `moduleCall` |
| `shared/dns/` | `"dnsResolver": true` | protected off-tunnel резолв ваших dial-таргетов (`newProtectedResolver`/`LookupHost`): TTL-кэш + single-flight + прямой UDP-запрос к `DNS_SERVERS` через ваш же `dialControl` |

## Свой модуль — папкой рядом с образцом

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

Он печатает, что найдено, чего нет, и команду установки под вашу ОС. Коротко — три разных
требования, и путать их не надо:

| Что собираем | Чем | Кросс-компиляция |
|---|---|---|
| desktop-helper (`windows`/`linux`/`darwin`) | **только Go 1.26+** (эту версию требует `go.mod` модуля; с go1.21 Go догружает нужный тулчейн сам) | **да, с любого хоста на любую ОС** (`CGO_ENABLED=0`, C-тулчейн не нужен) |
| android-helper (`.so`, `c-shared`) | Go + **Android NDK** | **да, с любого хоста** |

⛔ **C-компилятор модулю не нужен, и UI вы не пишете.** Интерактивные действия (капча, логин, 2FA)
рисует клиент: модуль отправляет строку `ACTION_REQUIRED|<id>|<payloadB64>` с декларативным правилом,
а рендерер принадлежит хосту — Android `ModuleActionActivity`, Desktop `antinet-action` (идёт
вместе с клиентом, форкается для любого модуля). Легаси-поле `module.json: actionBinary`
объявлять не надо: на Android оно вообще не читается, на Desktop хостовый рендерер всегда
пробуется первым. Подробно — `MODULE_SYSTEM.md` § «C-тулчейн модулю не нужен».

Плюс Python 3 для самого `build.py`. **Android SDK, Gradle и AGP не нужны** ни для чего: модуль —
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
`examples/moduleopenflux/native/.../main.go` и соседние `.go` — это data-plane helper'а. **Оставьте как
есть** обязательную обвязку: SOCKS5-фронт на переданном хостом сокете, маркер готовности `ready`,
protect-fd сокетов, сабкоманды `summarize` и `normalize` (контракт — `MODULE_API.md` §2.3).

## 3. Публикация (чтобы AntiNet ставил по `antinet://`-ссылке и авто-обновлял)
1. **Сначала дескриптор, потом сборка.** В `module.json`: `updateUrl` — адрес, по которому манифест
   будет лежать, и поднятая `version`. Порядок именно такой, потому что `module.json` едет внутри
   каждого бандла: адрес, вписанный после сборки, до пользователей не доедет — у них не будет ни
   авто-проверки, ни рабочего «Поделиться модулем» (ссылка уйдёт без `m`, и получателю ставить
   неоткуда). Правите `updateUrl` позже — пересоберите и перезалейте бандлы.
   ⚠ Адрес манифеста обязан быть стабильным (файл на ветке, например
   `raw.githubusercontent.com/<owner>/<repo>/main/antinet-module.json`), его перезаписывают на каждый
   релиз. Release-ассет для манифеста не годится: у каждого релиза он свой, и запечённый в дескриптор
   адрес навсегда останется на старой версии. Сами ZIP'ы, наоборот, могут переезжать свободно.
2. Соберите релиз-артефакты:
   ```
   python build.py --module openflux --os all      # helper'ы под все цели → dist/
   python build.py --bundle --module openflux      # → dist-release/*.zip + antinet-module.json
   ```
3. Залейте на хостинг (например GitHub Releases) каждый `dist-release/*.zip`.
4. Откройте `dist-release/antinet-module.json`, впишите реальные URL'ы бандлов (`android[<abi>]` и
   `desktop[<os>_<arch>]` — все, что собрали: манифест без бандла под ABI устройства эта платформа
   отвергает целиком) и залейте его по адресу из шага 1.
5. Следующий релиз — снова с шага 1: без поднятой `version` авто-проверка обновления не увидит.
   Сравнение посегментно-числовое, так что «1.3.10» корректно новее «1.3.7».
6. Распространяйте install-ссылку (один тап «скачать и поставить») — её собирает сам AntiNet
   («Настройки → Модули → Поделиться модулем»), руками формат готовить не надо:
   `antinet://import?module=<base64url-no-pad JSON>`, где JSON =
   `{"s":"openflux","n":"OpenFlux","m":"<updateUrl>","h":"https://github.com/p1neappleXpress/OpenFlux"}`. Ключ `m` и есть
   `updateUrl`; без него получатель установить не сможет — диалог лишь предложит открыть `h`.

Полная спецификация публикации/авто-обновления/ссылки — **`MODULE_API.md` §2.5**.

## Контракт (кратко)
Helper обязан: обслуживать SOCKS5 на сокете, который дал хост; писать маркер `ready`; защищать
исходящие сокеты protect-fd; отвечать на `<helper> summarize <link>` (имя и сервер) и
`<helper> normalize <raw>`. Всё остальное — хендовер `handoverMode`, off-TUN, интерактивные действия,
настройки, тайминги, контракт восстановления — в `MODULE_API.md`.
