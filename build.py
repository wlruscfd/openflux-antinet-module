#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""
build.py — ЕДИНЫЙ сборщик helper-бинарей протокол-модулей AntiNet под ЛЮБУЮ ОС (MODULE_API.md §4–§5).

Интерактивный выбор ОС + модуля (или флаги). Helper'ы кросс-платформенны через build-tag split
(platform_android.go ↔ platform_other.go, см. MODULE_API §4):
  • android                 → c-shared .so через NDK clang (dlopen в слот-процессе, НЕ execve).
  • windows / linux / darwin → `go build` (CGO_ENABLED=0 — чистая кросс-компиляция без C-тулчейна) →
                               examples/<module>/dist/desktop/<os>_<arch>/<module>-helper[.exe].
                               Desktop-хост (Pascal) форкает этот бинарь как суб-процесс (момент 2:
                               EXE, не DLL — без второго Go-рантайма в процессе хоста).
  python build.py --package --module qwdtt        # самодостаточный архив для автора → dist-archive/
  python build.py --bundle  --module qwdtt        # release-бандлы desktop + манифест авто-обновления → dist-release/

Команды ниже запускаются ИЗ КАТАЛОГА, где лежит этот файл (в репозитории — `module_system/`,
в архиве автора — его корень). Префикс пути намеренно не указан: он у этих двух раскладок разный.

Примеры:
  python build.py                                  # полностью интерактивно
  python build.py --os linux   --module qwdtt      # qWDTT под Linux (хост-арх)
  python build.py --os windows --module masterdns --arch amd64
  python build.py --os android --module echo --abis arm64-v8a   # → .so + module.json
  python build.py --os all     --module qwdtt -y   # android + все desktop-ОС

Требует: Go — версию диктует `go`-директива go.mod конкретного модуля, `--doctor` сверит её с
установленной. Для android — ещё Android NDK (как у tools/build-module.py).
"""
import argparse
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

# Windows-консоль часто cp1251/cp866 → UnicodeEncodeError на ✓/кириллице. Форсим UTF-8 вывод.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = Path(__file__).resolve().parent  # module_system/
REPO = HERE.parent                       # корень AntiNet-репозитория
IS_WIN = os.name == "nt"
# Обзор системы (тулчейн, быстрый старт, публикация) — ОДИН документ, но имя у него зависит от
# раскладки: в репозитории это `module_system/README.md`, в авторском архиве он едет под именем
# `MODULE_SYSTEM.md`, потому что корневой README.md там занят точкой входа автора (cmd_package).
# Рантайм-сообщения обязаны называть тот файл, который у читателя реально есть, иначе `--doctor`
# в архиве отправляет автора к несуществующему пути.
SYSTEM_DOC = "MODULE_SYSTEM.md" if (HERE / "MODULE_SYSTEM.md").exists() else "module_system/README.md"
SHARED_OFFTUN = HERE / "shared" / "offtun"  # канон off-TUN socket-protect + десктопные protect-адаптеры, всегда
SHARED_PROTECT = HERE / "shared" / "protect"  # канон клиента protect-сервиса (Android), инжектируется всегда
SHARED_SOCKS5 = HERE / "shared" / "socks5"  # канон SOCKS5-протокола целиком (socks5:true)
SHARED_LIFECYCLE = HERE / "shared" / "lifecycle"  # канон lifecycle-примитивов helper'а, инжектируется всегда
SHARED_DNS = HERE / "shared" / "dns"  # канон protected off-tunnel резолвера (dnsResolver:true)
SHARED_HOSTPROTO = HERE / "shared" / "hostproto"  # канон протокола разговора с хостом, всегда
SHARED_ENTRY = HERE / "shared" / "entry"  # канон точек входа (C-ABI / argv), всегда

# ВСЕ каноны ОДНОЙ таблицей: она же задаёт инжект (inject_canons) и она же уезжает в авторский
# архив (cmd_package через SHARED_CANONS). Заводишь новый канон — добавляешь СТРОКУ сюда, и он
# сам подхватывается обоими путями. Раньше список жил в cmd_package отдельными строками, и socks5
# туда не попал: архив echo/qWDTT собирался вне репо с «инжектировано 0» и падал на undefined
# parseSocksUDP.
#   gate    — ключ module.json; None = канон нужен КАЖДОМУ модулю и инжектится всегда;
#   android — участвует ли в android-сборке. У off-TUN стоит False: все его файлы отсечены
#             build-тегами от android (`linux && !android`, windows, darwin), там изоляцию даёт
#             protect-сервис, и копировать заведомо неприменимое в дерево незачем.
#
# ⚠ `offtun` инжектится БЕЗУСЛОВНО, хотя раньше гейтился ключом `offTun`. Причина: десктопная
# половина protect-адаптеров (`dialControl`/`protectFdFunc`) живёт именно здесь, и без неё общий
# код модуля не собирается под desktop вовсе. Новой зависимости это не добавляет — `offtun_*.go`
# тянут тот же `golang.org/x/sys`, который и так обязателен из-за `lifecycle`. Ключ `offTun` в
# дескрипторах больше ничего не гейтит и снят.
CANONS = (
    {"dir": SHARED_OFFTUN, "glob": "offtun_*.go", "label": "off-TUN", "gate": None, "android": False},
    {"dir": SHARED_PROTECT, "glob": "protect_*.go", "label": "protect", "gate": None, "android": True},
    {"dir": SHARED_LIFECYCLE, "glob": "lifecycle_*.go", "label": "lifecycle", "gate": None, "android": True},
    {"dir": SHARED_HOSTPROTO, "glob": "hostproto*.go", "label": "hostproto", "gate": None, "android": True},
    {"dir": SHARED_ENTRY, "glob": "entry_*.go", "label": "entry", "gate": None, "android": True},
    {"dir": SHARED_SOCKS5, "glob": "socks5shared*.go", "label": "socks5", "gate": "socks5", "android": True},
    {"dir": SHARED_DNS, "glob": "dns_*.go", "label": "dns", "gate": "dnsResolver", "android": True},
)
SHARED_CANONS = tuple(c["dir"] for c in CANONS)

# Реестр модулей строится из ЕДИНОГО дескриптора examples/<module>/module.json — ИСТОЧНИК ИСТИНЫ
# (schemes/name/description/homepage/handoverMode/parallelPing/helperBinary{android,desktop}/
#  build{goDir,goPkg,ldflags}). Плоские dist/<target>/module.json ГЕНЕРЯТСЯ из него
# (emit_android_descriptor/emit_desktop_descriptor) — НИКАКОГО дублирования описания.
# key реестра = имя каталога без префикса "module" (moduleecho→echo, modulemasterdns→masterdns).
def load_modules():
    mods = {}
    for mj in sorted((HERE / "examples").glob("*/module.json")):
        d = json.loads(mj.read_text(encoding="utf-8"))
        root = mj.parent                                            # examples/module<X>
        modname = root.name                                         # moduleecho
        key = modname[6:] if modname.startswith("module") else modname  # echo
        b = d.get("build", {})
        mods[key] = {
            "dir": (root / b["goDir"]).relative_to(REPO).as_posix(),  # каталог go.mod
            "root": root.relative_to(REPO).as_posix(),
            "pkg": b.get("goPkg", "."),
            "ldflags": b.get("ldflags", ""),
            "helper": d["helperBinary"]["android"],                 # android .so (c-shared, dlopen)
            "bin": d["helperBinary"]["desktop"],                    # desktop-бинарь (без расширения)
            "descriptor": d,                                        # полный дескриптор (для dist/<target>/module.json)
            "actbin": None,                                         # desktop actionBinary (UI-действие, §2.7) — cgo
        }
        ab = d.get("actionBinary")                                  # опц.: {desktop, goDir, goPkg} — webview-EXE и т.п.
        if ab and ab.get("desktop"):
            mods[key]["actbin"] = {
                "dir": (root / ab["goDir"]).relative_to(REPO).as_posix(),
                "pkg": ab.get("goPkg", "."),
                "bin": ab["desktop"],
            }
    return mods


MODULES = load_modules()

# Эталонный модуль: ЕГО архив несёт полный комплект доков модульной системы (контракт,
# внутренности хоста, обзор с тулчейном) и служит стартовой точкой тому, кто пишет СВОЙ модуль.
# Архивы остальных — авторская поставка: исходники модуля + каноны + сборка, без нашего SDK.
# Здесь константой, а не «if mod == 'echo'» по коду: точка одна, и переезд эталона на другой
# модуль не требует искать разбросанные сравнения.
DOCS_REFERENCE_MODULE = "echo"

def android_abi_list():
    """Канонический список Android-ABI — ЧИТАЕТСЯ из `tools/build-module.py` (`ABI_MAP`), а не
    дублируется здесь: второй список разойдётся с первым на первом же новом ABI."""
    import importlib.util
    src = HERE / "tools" / "build-module.py"
    spec = importlib.util.spec_from_file_location("_antinet_build_module", src)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return list(m.ABI_MAP.keys())


def _flat_descriptor_base(d, bundle_target):
    """Общие top-level поля дескриптора для ЛЮБОГО dist-манифеста (android/desktop) — единая база,
    чтобы копии не разъезжались при будущей правке. Caller добавляет свой backend-специфичный
    helperBinary поверх (+ легаси-actionBinary, если модуль его объявил).

    `bundle_target` — АРХИТЕКТУРА ИМЕННО ЭТОГО бандла: `arm64-v8a` для Android, `linux_amd64` для
    Desktop. Значение совпадает с ключом, под которым бандл лежит в манифесте обновления (§2.5), —
    имя одно и то же намеренно, чтобы автору было нечего сопоставлять в уме.
    ⚠ Это ПОДПИСЬ, а не пропуск: хост принимает решение «эта библиотека у нас не загрузится» по
    самому артефакту (ELF-заголовок / PE / Mach-O), а не по этому полю. Поле нужно двум другим:
    сборщику — поймать при публикации бандл, положенный не под тот ключ манифеста; хосту — сказать
    юзеру, ЧТО именно он принёс («бандл под arm64-v8a, устройство armeabi-v7a») вместо общей
    ошибки. Заявление автора и свойство файла могут разойтись, и тогда прав файл."""
    flat = {
        "apiVersion": d.get("apiVersion", 1),
        "schemes": d["schemes"],
        "name": d.get("name", ""),
        "description": d.get("description", ""),
        "homepage": d.get("homepage", ""),
        "parallelPing": d.get("parallelPing", False),
        # Модуль выдерживает ВТОРУЮ одновременную сессию, поднятую ради пинга, пока первая
        # обслуживает активный коннект (хост тогда держит её под ключом `<схема>#ping` и не
        # выселяет коннект). Свойство модуля, а не хоста: со стороны хоста два экземпляра
        # безопасны, а вот выдержит ли две сессии протокол/сервер — решает автор модуля.
        "pingWhileConnected": d.get("pingWhileConnected", False),
        "handoverMode": d.get("handoverMode", "restart"),
        # Причины события хоста, которые модуль РАЗБИРАЕТ (§2.8). Не объявил → хост шлёт ему
        # только `handover`, подменяя им любую другую причину: поведение ровно как до появления
        # причин. Пустой список в дескриптор не пишем — отсутствие ключа и есть «только handover».
        **({"hostEvents": d["hostEvents"]} if d.get("hostEvents") else {}),
        "relayWindowSec": d.get("relayWindowSec", 0),
        # Версия ПОСТАВКИ + куда ходить за обновлением. Оба обязаны доехать до установленного
        # модуля: без `version` хосту не с чем сравнивать манифест (любая версия выглядит новее),
        # без updateUrl авто-проверка не запускается вовсе. Раньше версия жила в build.gradle
        # APK-обвязки — с уходом APK единственный источник это module.json.
        # ⛔ Отдельного монотонного `versionCode` НЕТ и не заводить: две версии на один артефакт
        # (машинная + показываемая) неизбежно разъезжаются, а автор правит только вторую. Ключ
        # ровно один — `version` («1.3.7»), и его читают ОБА хоста
        # (`ModuleManager.kt::installedModules` J_VERSION → compareModuleVersions,
        #  `modulemanager.pas::ParseModuleJson` 'version' → CompareModuleVersions).
        "version": str(d.get("version", "")).strip(),
        "bundleTarget": bundle_target,
    }
    if d.get("updateUrl"):
        flat["updateUrl"] = d["updateUrl"]
    if d.get("names"):
        flat["names"] = d["names"]
    # lifecycle-тайминги (опц.; emit ТОЛЬКО если автор объявил — иначе платформа берёт built-in DEFAULT).
    for _k in ("crashLoopMaxDeaths", "crashLoopWindowSec", "heartbeatSec", "handoverDebounceSec"):
        if d.get(_k):
            flat[_k] = d[_k]
    # §2.10 ping-контракт — ОБА ключа реально читаются ОБОИМИ хостами
    # (`ModuleManager.kt` J_PING_TIMEOUT_SEC/J_PING_NEEDS_CONSENT; `modulemanager.pas`
    # ParseModuleJson → PingTimeoutMsImpl/CanPing-гейт), поэтому эмиттер обязан их доносить.
    # Цена дропа не
    # косметическая: echo объявляет pingNeedsConsent=true → без ключа фоновая волна пингует
    # его без canping-гейта, helper встаёт на подтверждение, fast-decline → ложный -2 (ровно
    # то, ради чего §2.10-гейт и вводился); masterdns объявляет pingTimeoutSec=60 (DNS-туннель
    # медленный) → без ключа floor падает на DEFAULT 20с → ложный -2 на ЖИВОМ модуле.
    # Флаги канон-инъекций (`socks5` / `dnsResolver`) сознательно НЕ эмитим — они
    # build-time-only (их читает только таблица CANONS этого файла), рантайм-читателей нет ни на
    # одной платформе (проверено грепом).
    if d.get("pingTimeoutSec"):
        flat["pingTimeoutSec"] = d["pingTimeoutSec"]
    if d.get("pingNeedsConsent"):
        flat["pingNeedsConsent"] = True
    # настройки модуля (опц.; хост читает массив as-is из dist module.json — § настройки модулей).
    if d.get("settings"):
        flat["settings"] = d["settings"]
    return flat


def emit_desktop_descriptor(mod, goos, goarch, out_dir):
    """Кладёт рядом с desktop-бинарём module.json (плоский) — его читает Desktop-хост (discovery).
    helperBinary = имя desktop-бинаря (+.exe на windows); остальные ключи — из дескриптора."""
    d = MODULES[mod]["descriptor"]
    ext = ".exe" if goos == "windows" else ""
    flat = _flat_descriptor_base(d, f"{goos}_{goarch}")
    flat["helperBinary"] = d["helperBinary"]["desktop"] + ext
    # actionBinary (UI-действие §2.7) — имя бинаря (+.exe на windows); modulemanager.ParseModuleJson читает.
    ab = MODULES[mod].get("actbin")
    if ab:
        flat["actionBinary"] = ab["bin"] + ext
    (out_dir / "module.json").write_text(
        json.dumps(flat, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")


def emit_android_descriptor(mod, abi, out_dir):
    """Кладёт рядом с `.so` module.json (плоский) — его читает Android-хост (`ModuleManager.discover`
    сканирует `files/modules/<id>/`). Симметрично emit_desktop_descriptor: одна и та же плоская схема,
    отличается только backend-специфичный helperBinary.

    Появился с уходом APK: раньше эти же ключи ехали meta-data'ой в манифесте APK-обёртки, и каталог
    `dist/android/<abi>/` нёс голую `.so` без единого описания. Теперь ABI-каталог самодостаточен —
    ровно то, что распаковывается в `files/modules/<id>/` на устройстве."""
    d = MODULES[mod]["descriptor"]
    flat = _flat_descriptor_base(d, abi)
    # Object form, NOT a flat string. Плоская строка на Desktop-стороне однозначно означает
    # «имя desktop-бинаря», и Android-читатель её попросту не разбирает: `ModuleManager.kt`'s
    # discover() делает `optJSONObject("helperBinary")?.optString("android")` — на строке это молча
    # даёт null, модуль пропускается без единой ошибки.
    flat["helperBinary"] = {"android": d["helperBinary"]["android"]}
    (out_dir / "module.json").write_text(
        json.dumps(flat, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")


# ⛔ WASM-хостинга нет: цели сборки только android (c-shared .so) и desktop (нативный бинарь).
# Дескриптор `dist/wasm/module.json` не генерируется, ключи `helperBinary.wasm`/`build.wasmGoPkg`
# не читает ни одна платформа (MODULE_API.md §2.12).


# ⛔ Генератора `<meta-data com.antinet.module.*>` для AndroidManifest.xml здесь нет и не нужно:
# модуль — файл, а не приложение, APK-обвязки у него не существует. Discovery на Android читает
# `files/modules/<id>/module.json` (см. emit_android_descriptor), а не `queryIntentServices`, —
# поэтому дескриптор нигде не дублируется.
DESKTOP_OSES = ["windows", "linux", "darwin"]
ALL_OSES = ["android"] + DESKTOP_OSES


def c(txt, code):
    return f"\033[{code}m{txt}\033[0m" if sys.stdout.isatty() else txt


def info(m): print(c("• ", "36") + m)
def ok(m):   print(c("✓ ", "32") + m)
def err(m):  print(c("✗ ", "31") + m, file=sys.stderr)


def ask(prompt, default=None):
    sfx = f" [{default}]" if default else ""
    try:
        v = input(c("? ", "35") + prompt + sfx + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); sys.exit(1)
    return v or (default or "")


def ask_choice(prompt, choices, default):
    while True:
        v = ask(f"{prompt} ({'/'.join(choices)})", default)
        if v in choices:
            return v
        err(f"Неверно: {v}. Допустимо: {choices}")


def find_go():
    g = shutil.which("go")
    if g:
        return g
    cand = Path(os.environ.get("GOROOT", "")) / "bin" / ("go.exe" if IS_WIN else "go")
    return str(cand) if cand.exists() else None


# ─────────────────────────────── ПРЕФЛАЙТ ТУЛЧЕЙНА ───────────────────────────────
#
# Зачем отдельным блоком, а не «упало — сам разберётся»: у автора стороннего модуля на руках
# только этот архив, и сообщение «go build упал (код 1)» ему не говорит НИЧЕГО о том, чего не
# хватает и где это взять. Проверка идёт ДО первой сборки и печатает ровно две вещи: чего нет и
# команду установки для ЕГО хост-ОС.
#
# ⚠ Три РАЗНЫХ требования, и путать их нельзя — именно на этом и застревают:
#   1. helper под desktop (windows/linux/darwin) — нужен ТОЛЬКО Go. `CGO_ENABLED=0`, то есть
#      кросс-компиляция с любого хоста на любой таргет без C-тулчейна вообще.
#   2. helper под android — Go + Android NDK (clang из него), тоже кросс с любого хоста.
#   3. actionBinary (опциональный UI-бинарь модуля, `module.json: actionBinary`) — cgo, а значит
#      C-тулчейн ХОСТА, и собрать его можно ТОЛЬКО на целевой ОС. Для модуля без actionBinary
#      этот пункт не существует; `build.py` его и не проверяет.

# ⛔ Минимальная версия Go — НЕ константа: её диктует `go`-директива в go.mod САМОГО модуля, и
# второе число рядом с ней гарантированно с ней разъезжается. Так и было: здесь стояло (1,23) при
# `go 1.25.0` у echo и `go 1.26` у qwdtt — `--doctor` отвечал «всё на месте» человеку с Go 1.23, а
# `go build` падал на `go.mod requires go >= 1.25.0`, т.е. проверка пропускала ровно тот случай,
# ради которого написана. Пол нужен только когда модуль не задан (общий `--doctor`) или go.mod не
# читается — тогда проверяем хоть что-то вместо того, чтобы молча пропустить любую версию.
GO_FLOOR = (1, 23)


GO_TOOLCHAIN_SWITCH_MIN = (1, 21)   # с go1.21 Go умеет сам ставить тулчейн, которого требует go.mod


def go_can_fetch_toolchain(go, installed):
    """Догрузит ли Go недостающий тулчейн сам. Проверять обязательно: `go.mod` МОЖЕТ требовать
    версию новее установленной, и это НЕ ошибка — при `GOTOOLCHAIN=auto` (дефолт с go1.21) Go
    скачивает нужный тулчейн на месте. Замер: при go1.25.4 в PATH `go version` внутри каталога
    qwdtt (`go 1.26`) отвечает go1.26.0. Гейт без этой проверки объявлял бы неудовлетворённым
    ровно то окружение, в котором сборка проходит."""
    if installed and installed < GO_TOOLCHAIN_SWITCH_MIN:
        return False
    try:
        r = subprocess.run([go, "env", "GOTOOLCHAIN"], capture_output=True, text=True, timeout=20)
        return r.returncode == 0 and r.stdout.strip() != "local"
    except Exception:                                            # noqa: BLE001 — диагностика, не поток
        return False


def go_required_for(mod):
    """Версия Go, которую требует go.mod модуля. GO_FLOOR — если модуль не указан/не прочитался."""
    m = MODULES.get(mod) if mod else None
    if not m:
        return GO_FLOOR
    try:
        for line in (REPO / m["dir"] / "go.mod").read_text(encoding="utf-8").splitlines():
            if line.startswith("go "):
                major, minor = line.split()[1].split(".")[:2]
                return (int(major), int(minor))
    except Exception:                                            # noqa: BLE001 — диагностика, не поток
        pass
    return GO_FLOOR


HOST_OS = "windows" if IS_WIN else ("darwin" if sys.platform == "darwin" else "linux")

# Как поставить — по хост-ОС. Держим ТЕКСТОМ рядом с проверкой, а не в доке: доку автор читает до
# сборки, а сообщение об отсутствии — в момент, когда оно нужно.
INSTALL_HINTS = {
    "go": {
        "windows": "winget install --id GoLang.Go -e   (или ZIP/MSI с https://go.dev/dl/)",
        "linux": "sudo apt install golang-go   (Debian/Ubuntu; либо tarball с https://go.dev/dl/ в /usr/local)",
        "darwin": "brew install go   (или PKG с https://go.dev/dl/)",
    },
    "ndk": {
        "windows": "Android Studio → SDK Manager → SDK Tools → NDK (Side by side);\n"
                   "      либо cmdline-tools: sdkmanager \"ndk;27.2.12479018\";\n"
                   "      либо ZIP с https://developer.android.com/ndk/downloads\n"
                   "      затем:  setx ANDROID_NDK_HOME \"C:\\Android\\Sdk\\ndk\\27.2.12479018\"",
        "linux": "sdkmanager \"ndk;27.2.12479018\"  либо ZIP с https://developer.android.com/ndk/downloads\n"
                 "      затем:  export ANDROID_NDK_HOME=$HOME/Android/Sdk/ndk/27.2.12479018",
        "darwin": "sdkmanager \"ndk;27.2.12479018\"  либо ZIP с https://developer.android.com/ndk/downloads\n"
                  "      затем:  export ANDROID_NDK_HOME=$HOME/Library/Android/sdk/ndk/27.2.12479018",
    },
    "cc": {
        "windows": "MSYS2 + MinGW-w64:  winget install -e --id MSYS2.MSYS2\n"
                   "      затем в MSYS2:  pacman -S mingw-w64-x86_64-gcc   и добавь ...\\mingw64\\bin в PATH",
        "linux": "sudo apt install build-essential libgtk-3-dev libwebkit2gtk-4.1-dev\n"
                 "      (webkit2gtk нужен только модулям с webview-actionBinary)",
        "darwin": "xcode-select --install",
    },
}


def _capture(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


def go_version_of(go):
    """(major, minor) из `go version`, либо None если не разобралось."""
    m = re.search(r"go(\d+)\.(\d+)", _capture([go, "version"]))
    return (int(m.group(1)), int(m.group(2))) if m else None


def find_cc():
    """C-компилятор хоста — нужен ТОЛЬКО для cgo-actionBinary (см. шапку блока)."""
    for name in ("gcc", "clang", "cc"):
        p = shutil.which(name)
        if p:
            return p
    return None


def check_toolchain(targets, mod=None, abis="arm64-v8a", api=26):
    """Проверяет ровно то, что нужно ДЛЯ ЗАПРОШЕННЫХ таргетов. Возвращает список проблем
    (пустой = всё на месте). Печатает найденное — чтобы автор видел не только дыры, но и версии,
    по которым потом сверять багрепорт."""
    problems = []

    need = go_required_for(mod)
    go = find_go()
    if not go or not Path(go).exists():
        problems.append(("Go (go%d.%d+)" % need, INSTALL_HINTS["go"][HOST_OS]))
    else:
        v = go_version_of(go)
        if v and v < need and not go_can_fetch_toolchain(go, v):
            problems.append((f"Go {v[0]}.{v[1]} слишком старый — go.mod модуля требует "
                             f"go{need[0]}.{need[1]}+", INSTALL_HINTS["go"][HOST_OS]))
        elif v and v < need:
            info(f"  Go {v[0]}.{v[1]} младше требуемой go{need[0]}.{need[1]} — Go скачает нужный "
                 f"тулчейн сам (GOTOOLCHAIN=auto), сборке это не мешает")
        else:
            ok(f"Go: {go}" + (f"  (go{v[0]}.{v[1]})" if v else ""))

    if "android" in targets:
        sys.path.insert(0, str(HERE / "tools"))
        ndk = None
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("_bm", HERE / "tools" / "build-module.py")
            bm = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(bm)
            ndk = bm.find_ndk()
        except Exception as e:                                   # noqa: BLE001 — диагностика, не поток
            info(f"  (не удалось спросить NDK у tools/build-module.py: {e})")
        if not ndk or not Path(ndk).is_dir():
            problems.append(("Android NDK (переменная ANDROID_NDK_HOME / ANDROID_HOME/ndk/<ver>)",
                             INSTALL_HINTS["ndk"][HOST_OS]))
        else:
            ok(f"Android NDK: {ndk}")

    # actionBinary — только если модуль его объявил И среди таргетов есть ХОСТОВАЯ ОС.
    # Кросс-компиляция здесь невозможна по построению (cgo + системные библиотеки цели), поэтому
    # для чужой ОС проверять C-тулчейн бессмысленно — сборка этого бинаря там и не запускается.
    if mod and MODULES.get(mod, {}).get("actbin") and HOST_OS in targets:
        cc = find_cc()
        if not cc:
            problems.append((f"C-компилятор для actionBinary модуля '{mod}' (cgo, только на {HOST_OS})",
                             INSTALL_HINTS["cc"][HOST_OS]))
        else:
            ok(f"C-компилятор (для actionBinary): {cc}")

    return problems


def report_toolchain(problems):
    """Печатает дыры + как их закрыть. Возвращает True, если всё на месте."""
    if not problems:
        return True
    print()
    err("Не хватает инструментов для запрошенных целей:")
    for what, how in problems:
        print(c("  ✗ ", "31") + what)
        print(c("    → ", "33") + how)
    print()
    info(f"Что для чего нужно (полностью — {SYSTEM_DOC} § Тулчейн):")
    print("  • desktop-helper (windows/linux/darwin) — ТОЛЬКО Go: CGO_ENABLED=0, кросс с любого хоста")
    print("  • android-helper                        — Go + Android NDK, тоже кросс с любого хоста")
    print("  • actionBinary (если модуль его объявил) — cgo, собирается ТОЛЬКО на целевой ОС")
    return False


def cmd_doctor(targets, mod):
    print(c("=== Проверка тулчейна ===", "1;36"))
    info(f"Хост: {HOST_OS} · цели: {targets}" + (f" · модуль: {mod}" if mod else ""))
    print()
    problems = check_toolchain(targets, mod)
    if report_toolchain(problems):
        print()
        ok("Всё на месте — можно собирать.")
        return True
    return False


def inject_canons(m, go_dir, android=False):
    """Копирует каноны shared/* в main-пакет helper'а ПЕРЕД сборкой; возвращает список
    скопированных путей для очистки в finally. В git у модуля этих файлов нет — канон один.

    Что и когда инжектится — целиком в таблице CANONS выше; здесь развилки нет ни одной,
    потому что четыре прежние функции (inject_offtun/protect/socks5/lifecycle) различались
    РОВНО значениями трёх полей — каталог, маска, подпись — и при добавлении пятого канона
    превратились бы в пятую копию того же тела."""
    main_dir = (go_dir / m["pkg"]).resolve()
    copied = []
    for c in CANONS:
        if android and not c["android"]:
            continue
        if c["gate"] and not m["descriptor"].get(c["gate"]):
            continue
        n = 0
        for src in sorted(c["dir"].glob(c["glob"])):
            dst = main_dir / src.name
            # ⛔ Своего файла с тем же именем у модуля быть не должно: инжект бы его ЗАТЁР, а
            # finally-очистка потом УДАЛИЛА — то есть исходник модуля исчез бы молча, и заметил бы
            # это автор уже после сборки. Падаем громко и называем конфликтующий путь.
            if dst.exists():
                raise SystemExit(
                    f"канон {c['label']}: файл модуля {dst} конфликтует с каноном {src.name}.\n"
                    f"Переименуй свой файл — этот код даёт канон (shared/{c['dir'].name}/).")
            shutil.copy2(str(src), str(dst))
            copied.append(dst)
            n += 1
        info(f"  {c['label']}: инжектировано {n} {c['glob']} → {main_dir.relative_to(REPO).as_posix()}")
    return copied


def build_desktop(go, mod, goos, goarch):
    """go build helper'а под desktop-ОС (CGO_ENABLED=0 → кросс-компиляция без C-тулчейна)."""
    m = MODULES[mod]
    go_dir = REPO / m["dir"]
    if not (go_dir / "go.mod").exists():
        err(f"go.mod не найден: {go_dir}"); return False
    ext = ".exe" if goos == "windows" else ""
    out = REPO / m["root"] / "dist" / "desktop" / f"{goos}_{goarch}" / (m["bin"] + ext)
    out.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="0")
    cmd = [go, "build", "-trimpath"]
    if m["ldflags"]:
        cmd.append(f"-ldflags={m['ldflags']}")
    cmd += ["-o", str(out), m["pkg"]]
    info(f"[{mod}/{goos}_{goarch}] {' '.join(cmd[1:])}")
    # Каноны shared/* → main-пакет helper'а, собираем, в finally УДАЛЯЕМ копии (в git per-module
    # их нет). Состав и гейты — таблица CANONS.
    injected = inject_canons(m, go_dir)
    try:
        r = subprocess.run(cmd, cwd=str(go_dir), env=env)
    finally:
        for p in injected:
            try:
                p.unlink()
            except OSError:
                pass
    if r.returncode != 0:
        err(f"[{mod}/{goos}_{goarch}] go build упал (код {r.returncode})"); return False
    sz = out.stat().st_size if out.exists() else 0
    ok(f"[{mod}/{goos}_{goarch}] → {out}  ({sz} байт)")
    # actionBinary (UI-действие §2.7, напр. webview-капча) — CGO_ENABLED=1 (нативный webview-тулчейн), потому
    # собирается ТОЛЬКО под ХОСТ-ОС (cgo+webkit/WebView2 кросс-компилировать нельзя). Под другую ОС — собрать там.
    ab = m.get("actbin")
    if ab:
        import platform as _pf
        host = {"Windows": "windows", "Linux": "linux", "Darwin": "darwin"}.get(_pf.system(), "")
        if goos != host:
            info(f"[{mod}] actionBinary '{ab['bin']}' пропущен для {goos} (cgo/webview — собери на целевой ОС)")
        else:
            abdir = REPO / ab["dir"]
            about = out.parent / (ab["bin"] + ext)
            if not (abdir / "go.mod").exists():
                info(f"[{mod}] actionBinary go.mod не найден: {abdir}")
            else:
                aenv = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="1")
                ar = subprocess.run([go, "build", "-trimpath", "-o", str(about), ab["pkg"]], cwd=str(abdir), env=aenv)
                if ar.returncode != 0:
                    err(f"[{mod}] actionBinary build упал (код {ar.returncode}) — UI-действие не заработает")
                else:
                    ok(f"[{mod}] actionBinary → {about}  ({about.stat().st_size if about.exists() else 0} байт)")
    emit_desktop_descriptor(mod, goos, goarch, out.parent)   # module.json рядом с бинарём (Desktop discovery)
    # per-OS installer-скрипт модуля (распространяемый; кладёт файлы + ставит нативные prereq UI-действия:
    # Windows WebView2 / Linux webkit2gtk — §2.7). Источник в корне модуля (трекается), копируем в бандл.
    inst = {"windows": "install-windows.ps1", "linux": "install-linux.sh", "darwin": "install-darwin.sh"}.get(goos)
    if inst:
        isrc = REPO / m["root"] / inst
        if isrc.exists():
            shutil.copy2(str(isrc), str(out.parent / inst))
            ok(f"[{mod}/{goos}_{goarch}] installer → {inst}")
    return True


# ⛔ Цели `wasm` (GOOS=wasip1) нет — см. MODULE_API.md §2.12.


def build_android(mod, abis, api):
    """Делегирует tools/build-module.py (NDK c-shared .so → dist/android/<abi>/).

    ⚠ Артефакт — разделяемая библиотека (`-buildmode=c-shared`), а НЕ исполняемый PIE.
    Скачанный файл на Android нельзя `execve` (W^X, API 29+), но можно `dlopen` — слот-процесс
    грузит .so шимом и зовёт единственный C-ABI-экспорт `antinet_module_run`.

    Рядом с каждой `.so` кладётся module.json — ABI-каталог самодостаточен и распаковывается в
    `files/modules/<id>/` как есть (симметрично dist/desktop/<os>_<arch>/)."""
    m = MODULES[mod]
    cmd = [sys.executable, str(HERE / "tools" / "build-module.py"),
           "--go-dir", str(REPO / m["dir"]), "--go-pkg", m["pkg"],
           f"--ldflags={m['ldflags']}", "--helper", m["helper"],
           "--out-jnilibs", str(REPO / m["root"] / "dist" / "android"),  # единый dist/ (как desktop)
           "--abis", abis, "--api", str(api), "-y"]
    info(f"[{mod}/android] → tools/build-module.py (abis={abis})")
    # Каноны инжектим и здесь: android-сборка делегируется в tools/build-module.py, а тот про
    # shared/ ничего не знает. Убираем в finally: per-module копий в git нет, канон один.
    injected = inject_canons(m, REPO / m["dir"], android=True)
    try:
        rc = subprocess.run(cmd).returncode
    finally:
        for p in injected:
            try:
                p.unlink()
            except OSError:
                pass
    if rc != 0:
        return False
    dist_root = REPO / m["root"] / "dist" / "android"
    for abi_dir in sorted(dist_root.iterdir()) if dist_root.is_dir() else []:
        if not abi_dir.is_dir() or not (abi_dir / m["helper"]).is_file():
            continue
        # `-buildmode=c-shared` попутно пишет C-заголовок экспортов. Он нужен только тому, кто
        # линкуется с библиотекой на C — наш шим объявляет прототип сам (`dlsym`). На устройстве
        # это мёртвый груз, а каталог целиком уезжает в бандл — убираем сразу.
        for stale in abi_dir.glob("*.h"):
            stale.unlink()
        emit_android_descriptor(mod, abi_dir.name, abi_dir)
    return True


# ─────────────────────── package: самодостаточный архив модуля для автора ───────────────────────
# `build.py --package --module <X>` собирает ZIP, который можно отдать автору протокола: исходники
# модуля + кросс-платформенная сборочная система (этот build.py + tools + shared/offtun) + доки +
# Автор распаковывает → `python build.py --module <X> --os all` (helper'ы под все цели → dist/).
# Публикация (antinet://-ссылка + авто-обновление) — `--bundle` + MODULE_API §2.5.

def read_module_version(m):
    """`version` из module.json — для скелета манифеста авто-обновления (§2.5).

    Раньше читалось из `build.gradle.kts` APK-обвязки: версия модуля была версией его APK. С уходом
    APK единственный источник — сам дескриптор, и это же значение едет в установленный module.json
    как baseline, с которым хост сравнивает манифест."""
    return str(m["descriptor"].get("version", "")).strip()


README_ARCHIVE_TEMPLATE = """# Модуль «__NAME__» для AntiNet (`__SCHEME__://`)

Самодостаточный архив протокол-модуля AntiNet: исходники модуля + кросс-платформенная сборочная
система + документация. Собирается под **Android + Windows/Linux/macOS** без репозитория AntiNet.

Домашняя страница протокола: __HOMEPAGE__

## Что внутри

| Путь | Что это |
|---|---|
| `README.md` | этот файл — точка входа |
__DOCS_ROWS__| `build.py` | сборщик helper-бинарей под все ОС. `python build.py --help`, `--doctor` |
| `tools/build-module.py` | низкоуровневый Android-билдер (NDK clang → `.so`), зовётся из `build.py` |
| `examples/__MODNAME__/` | **сам модуль-образец**: `module.json` (ЕДИНЫЙ дескриптор) + `native/` (Go data-plane) |
| `shared/` | **каноны** — общий код всех модулей. `build.py` копирует их в main-пакет helper'а ПЕРЕД сборкой и убирает после; в дереве модуля их нет и класть туда не надо |
| `antinet-module.example.json` | образец манифеста авто-обновления (реальный генерит `--bundle`) |
| `LICENSE` | лицензия сборочной системы и канонов — **MIT**. Лицензия САМОГО модуля — `__LICENSE_ID__`, см. ниже |

## Лицензия

__LICENSE_SECTION__

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
cp -r examples/__MODNAME__ examples/modulemymod     # рядом, а не поверх
# → отредактировать examples/modulemymod/module.json: schemes / name / version /
#   helperBinary{android:"libmymod.so", desktop:"mymod-helper"} / build{goDir,goPkg}
python build.py --module mymod --os all             # ключ = имя папки без префикса "module"
```

Образец `__MODNAME__` при этом остаётся на месте — есть с чем сверяться.

## Требования (и как поставить)

Проверить хост одной командой:

```
python build.py --doctor --os all --module __MOD__
```

Он печатает, что найдено, чего нет и КОМАНДУ установки под твою ОС. Коротко — три РАЗНЫХ
требования, и путать их не надо:

| Что собираем | Чем | Кросс-компиляция |
|---|---|---|
| desktop-helper (`windows`/`linux`/`darwin`) | **только Go __GOMIN__+** (эту версию требует `go.mod` модуля; с go1.21 Go догружает нужный тулчейн сам) | **да, с любого хоста на любую ОС** (`CGO_ENABLED=0`, C-тулчейн не нужен) |
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
python build.py --module __MOD__ --os all        # Android .so + Windows/Linux/macOS helper
python build.py --module __MOD__ --os linux       # только Linux (хост-арх; --arch для другой)
python build.py --module __MOD__ --os android      # только Android .so
python build.py --module __MOD__ --os android --abis arm64-v8a,armeabi-v7a,x86_64
```
Результат — самодостаточный каталог на каждую цель (артефакт + `module.json`):
`examples/__MODNAME__/dist/desktop/<os>_<arch>/` и `examples/__MODNAME__/dist/android/<abi>/`.

## 2. Где править протокол
`examples/__MODNAME__/native/.../main.go` (+ соседние .go) — это data-plane helper'а. **ОСТАВЬ как есть**
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
   python build.py --module __MOD__ --os all      # helper'ы под все цели → dist/
   python build.py --bundle --module __MOD__      # → dist-release/*.zip + antinet-module.json
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
   `{"s":"__SCHEME__","n":"__NAME__","m":"<updateUrl>","h":"__HOMEPAGE__"}`. Ключ `m` и есть
   `updateUrl`; без него получатель установить не сможет — диалог лишь предложит открыть `h`.

Полная спецификация публикации/авто-обновления/ссылки — **`MODULE_API.md` §2.5**.

## Контракт (кратко)
Helper ОБЯЗАН: обслуживать SOCKS5 на сокете, который дал хост; писать маркер `ready`; защищать
исходящие сокеты protect-fd; отвечать на `<helper> summarize <link>` (имя+сервер) и
`<helper> normalize <raw>`. Опции (хендовер `handoverMode`, off-TUN, интерактив-действия, настройки,
тайминги, контракт восстановления) — `MODULE_API.md`.
"""


# ⚠ Лицензия архива НЕ одна: сборочная система и каноны — MIT всегда, а САМ модуль живёт под своей
# (`module.json: license`), и она может быть строже. Молча накрыть архив общим MIT нельзя: у qWDTT
# код производен от GPL-3.0-апстрима (замер: 85.9% совпадения по 19 одноимённым файлам, четыре
# идентичны на 100%), и MIT над ним был бы ложным утверждением о правах. Поэтому раздел собирается
# из дескриптора, а не пишется текстом в шаблоне.
def _is_internal_only(rel):
    """Отслеживается гитом, но в авторский архив НЕ едет.

    `antinet-<mod>.patch` — снимок дельты AntiNet над вендорнутым апстримом. Он существует ради
    НАШЕГО ре-вендоринга: поднять дерево с нуля от чистого архива апстрима. Получателю релиза он
    не нужен — полные исходники модуля у него уже есть, — и он ВРЕДЕН, потому что по построению
    исторический (не пересобирается на каждую правку) и успевает разойтись с деревом: у qWDTT из
    32 файлов патча 10 уже не существуют, и он воссоздаёт снятый `qwdtt-captcha/` (легаси
    actionBinary) и `protect_inject.go`/`socks5_common.go`, заменённые канонами `shared/`. Патч,
    дающий дерево, которое не собирается, хуже отсутствия патча."""
    return Path(rel).name.startswith("antinet-") and rel.endswith(".patch")


def _module_tracked_files(modroot):
    """Файлы модуля ПО ДАННЫМ GIT — это и есть «что здесь исходник».

    `.gitignore` уже описывает границу точно: апстрим-референс `qwdtt-upstream-*` (151 файл чужого
    Android-приложения), `qwdtt.bump-wip`, `.old-`-деревья, собранные бинари, вендорнутые git-базы.
    Держать вторую копию этих правил шаблонами в упаковщике — гарантированное расхождение, оно и
    случилось: шаблоны не знали про апстрим, и он уезжал в авторский архив.

    None — git недоступен (например, `--package` зовут из распакованного архива); вызывающий
    падает на шаблоны."""
    try:
        r = subprocess.run(["git", "ls-files", "-z", "--", modroot],
                           cwd=str(REPO), capture_output=True, timeout=120)
        if r.returncode != 0:
            return None
        out = [x for x in r.stdout.decode("utf-8", "replace").split("\0") if x]
        return out or None
    except Exception:                                            # noqa: BLE001 — диагностика, не поток
        return None


def _rmtree_force(path):
    """rmtree, переживающий read-only файлы. На Windows объекты git-хранилища создаются
    read-only, и голый `shutil.rmtree` падает на них `PermissionError` — из-за этого `--package`
    для masterdns не собирался вовсе (в его дереве лежит вендорнутая git-база)."""
    def _onexc(func, p, exc):
        os.chmod(p, stat.S_IWRITE)
        func(p)
    shutil.rmtree(path, onexc=_onexc)


def _nested_licenses(mod):
    """LICENSE-файлы ВНУТРИ дерева модуля — вендорнутые чужие проекты. Ищем, а не перечисляем
    руками: у masterdns внутри лежит MasterDnsVPN с ЧУЖИМ копирайтом под своим MIT, и «весь архив
    MIT» рядом с нашим `Copyright (c) AntiNet` читалось бы как присвоение. Список собирается сам,
    поэтому новый вендорнутый проект попадёт в README без правки этой функции."""
    root = REPO / MODULES[mod]["root"]
    out = []
    for p in sorted(root.rglob("LICENSE*")):
        rel = p.relative_to(root).as_posix()
        if "/" not in rel:
            continue                      # лицензия САМОГО модуля — она названа выше, не «вложенная»
        head = p.read_text(encoding="utf-8", errors="replace")[:400]
        name = "GPL-3.0" if "GNU GENERAL PUBLIC" in head.upper() else (
            "MIT" if "MIT License" in head else "см. файл")
        holder = next((ln.strip() for ln in head.splitlines()
                       if ln.strip().lower().startswith("copyright")), "")
        # В теле GPL первая copyright-строка — боилерплейт самой лицензии (FSF), а не правообладатель
        # кода. Показать её как «чей копирайт» значило бы соврать в атрибуции.
        if "Free Software Foundation" in holder:
            holder = ""
        out.append((rel, name, holder))
    return out


def _license_section(mod, d):
    lic = d.get("license", "MIT")
    nested = _nested_licenses(mod)
    tail = ""
    if nested:
        tail = ("\n\n**Вложенные деревья со своей лицензией и своим копирайтом** — их условия наш\n"
                "`LICENSE` не перекрывает, атрибуцию сохранять обязательно:\n\n"
                + "\n".join(f"- `{path}` — {name}"
                            + (f" · {holder}" if holder else "") for path, name, holder in nested))
    if lic == "MIT":
        return ("Сборочная система, каноны и код самого модуля — **MIT** (`LICENSE`). Делай что\n"
                "хочешь: свой модуль может быть закрытым, коммерческим, под любой другой лицензией.\n"
                "Единственное требование — сохранить текст лицензии и копирайт в копиях этого кода."
                + tail)
    return (f"⚠ Лицензий в архиве ДВЕ, и это не формальность.\n\n"
            f"- **Сборочная система и каноны** (`build.py`, `tools/`, `shared/`, доки) — **MIT**\n"
            f"  (`LICENSE` в корне архива).\n"
            f"- **Сам модуль** `examples/module{mod}/` — **{lic}** "
            f"(`examples/module{mod}/LICENSE`).\n\n"
            f"MIT совместим с {lic} в одну сторону: собранный из этого архива модуль распространяется\n"
            f"на условиях {lic}. Если делаешь свой модуль на базе канонов — на ТВОЙ код\n"
            f"распространяется MIT, и копилефт этого модуля тебя не касается: бери за образец echo,\n"
            f"а не этот модуль, если не хочешь наследовать {lic}." + tail)


def _docs_rows(mod):
    """Строки таблицы «что внутри» для доков системы. Их несёт только эталонный архив, поэтому
    и строки о них появляются только там — таблица обязана описывать РЕАЛЬНОЕ содержимое, иначе
    первое же действие читателя (открыть MODULE_API.md) упирается в отсутствующий файл."""
    if mod != DOCS_REFERENCE_MODULE:
        # Текст README ниже ссылается на эти доки по именам. Одна честная строка разрешает ВСЕ
        # такие ссылки разом — лучше, чем помечать каждое упоминание по отдельности.
        return ("| _(доков системы здесь нет)_ | `MODULE_API.md` / `MODULE_SYSTEM.md` / `PORTING.md` "
                "в этот архив не входят: он — авторская поставка модуля, а не SDK. Ссылки на них "
                f"ниже ведут в эталонный архив `{DOCS_REFERENCE_MODULE}-module` и в репозиторий "
                "AntiNet |\n")
    return (
        "| `MODULE_SYSTEM.md` | **обзор модульной системы**: из чего состоит модуль, тулчейн "
        "(какие компиляторы/NDK, кросс-компиляция), быстрый старт, публикация |\n"
        "| `MODULE_API.md` | **КОНТРАКТ** — что helper обязан предоставить, семантика каждого "
        "ключа `module.json`, все опции |\n"
        "| `PORTING.md` | внутренности AntiNet-стороны (кому портировать/чинить хост) |\n")


def gen_archive_readme(mod):
    m = MODULES[mod]
    d = m["descriptor"]
    return (README_ARCHIVE_TEMPLATE
            .replace("__MOD__", mod)
            .replace("__MODNAME__", Path(m["root"]).name)
            .replace("__NAME__", d.get("name", mod))
            .replace("__SCHEME__", d["schemes"][0])
            # Минимум Go берём ТЕМ ЖЕ примитивом, что и `--doctor` (`go_required_for`): вторая
            # цифра рядом с go.mod гарантированно с ней разъезжается — здесь и стояло «1.23+»
            # при `go 1.25.0` у echo и `go 1.26` у qwdtt.
            .replace("__GOMIN__", "%d.%d" % go_required_for(mod))
            .replace("__DOCS_ROWS__", _docs_rows(mod))
            .replace("__LICENSE_SECTION__", _license_section(mod, d))
            .replace("__LICENSE_ID__", d.get("license", "MIT"))
            .replace("__HOMEPAGE__", d.get("homepage", "") or "(не указана)"))


def cmd_package(mod):
    """Самодостаточный архив модуля для автора → dist-archive/<mod>-module-v<ver>.zip."""
    import zipfile
    m = MODULES[mod]
    root = REPO / m["root"]
    modname = Path(m["root"]).name
    vname = read_module_version(m)
    arch = HERE / "dist-archive"
    stage = arch / f"{mod}-module"
    if stage.exists():
        _rmtree_force(stage)
    stage.mkdir(parents=True)
    shutil.copy2(HERE / "build.py", stage / "build.py")
    (stage / "tools").mkdir()
    shutil.copy2(HERE / "tools" / "build-module.py", stage / "tools" / "build-module.py")
    for canon in SHARED_CANONS:
        shutil.copytree(canon, stage / "shared" / canon.name)
    dst_mod = stage / "examples" / modname
    tracked = _module_tracked_files(m["root"])
    if tracked is not None:
        for rel in tracked:
            src = REPO / rel
            if not src.is_file() or _is_internal_only(rel):
                continue
            dst = dst_mod / Path(rel).relative_to(m["root"])
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(str(src), str(dst))
        info(f"  состав модуля: {len(tracked)} файлов по данным git")
    else:
        # Фоллбэк, когда git недоступен: `--package` могут звать из РАСПАКОВАННОГО архива, где
        # никакого репозитория нет. Шаблоны заведомо грубее git'а — они не знают про
        # апстрим-референсы и `.old-`/`bump-wip`-деревья, — поэтому это запасной путь, а не основной.
        ign = shutil.ignore_patterns(
            "dist", "dist-release", "build", ".gradle", "__pycache__", ".git*", "*.pyc",
            "*.zip", "*.exe", "*.so", "*.dll", "*.dylib", "*.aar")
        shutil.copytree(root, dst_mod, ignore=ign)
        info("  состав модуля: по шаблонам (git недоступен)")

    # ⚠ Пути внутри доков репо-относительные (`module_system/build.py`), а в архиве префикса
    # `module_system/` нет. Чиним ЗДЕСЬ, а не «автор догадается»: доку, команды из которой не
    # работают копипастом, автор перестаёт читать после первой же неудачи. Правило одно на все
    # доки архива — отсюда общая функция, а не похожие замены по местам.
    # Второе, что чинит та же функция: доки ссылаются на ВСЕ референс-модули репозитория, а архив
    # несёт РОВНО ОДИН. Ссылка на чужой модуль у автора не разрешается — помечаем её как внешнюю,
    # вместо того чтобы вырезать (сам референс полезен, он просто лежит не здесь). Список берём из
    # реестра, а не хардкодом: `--package` любого модуля обязан пометить все ОСТАЛЬНЫЕ, поэтому
    # добавление четвёртого модуля не требует правки этой функции.
    foreign = [Path(o["root"]).name for k, o in MODULES.items() if k != mod]

    def _repo_paths_to_archive(text):
        text = (text.replace("module_system/build.py", "build.py")
                    .replace("module_system/examples/", "examples/")
                    .replace("module_system/shared/", "shared/")
                    .replace("module_system/dist-archive/", "dist-archive/")
                    .replace("`module_system/`", "корня архива"))
        for fm in foreign:
            text = text.replace(f"`examples/{fm}/", f"`(репозиторий AntiNet) examples/{fm}/")
        return text

    # LICENSE — ОБЯЗАТЕЛЕН в архиве, а не «желателен»: без него опубликованные исходники по
    # умолчанию под полным авторским правом, т.е. автор формально не вправе ни собрать образец,
    # ни сделать на его основе свой модуль — ровно то, ради чего архив и существует.
    shutil.copy2(HERE / "LICENSE", stage / "LICENSE")
    # Доки МОДУЛЬНОЙ СИСТЕМЫ (контракт, внутренности хоста, обзор) едут ТОЛЬКО с эталонным
    # архивом. Остальные два — авторская поставка: исходники модуля + каноны + сборка, то есть
    # ровно то, что публикует автор своего модуля. Класть ему в архив наш контракт и внутренности
    # AntiNet-стороны незачем: они не про его модуль, устаревают отдельно от него, и читатель его
    # релиза пришёл за модулем, а не за SDK. Кто пишет СВОЙ модуль — берёт эталонный архив.
    if mod == DOCS_REFERENCE_MODULE:
        for doc in ("MODULE_API.md", "PORTING.md"):
            shutil.copy2(HERE / doc, stage / doc)
        # module_system/README.md — обзор системы + ТУЛЧЕЙН + карта папок. Едет под именем
        # MODULE_SYSTEM.md, потому что корневой README.md в архиве занят точкой входа автора.
        (stage / "MODULE_SYSTEM.md").write_text(
            "<!-- Копия module_system/README.md из репозитория AntiNet. Пути приведены к раскладке\n"
            "     этого архива: префикс `module_system/` в нём отсутствует. -->\n\n"
            + (HERE / "README.md").read_text(encoding="utf-8"), encoding="utf-8")

    # ⛔ ОДИН проход по ВСЕМ .md стейджа — ровно потому, что правило заявлено единым. Пока правка
    # висела на перечне файлов, доки утекали мимо неё поштучно: MODULE_API.md и PORTING.md ехали
    # `shutil.copy2`, README канонов — внутри `copytree(shared/)`, и `python module_system/build.py`
    # из контракта у автора не работал. Перечень файлов и не мог быть полным: каждый новый док
    # добавляется копированием, а про список замен вспоминают потом. Замены идемпотентны
    # (результат под шаблон не подпадает), поэтому проход безопасен для уже приведённых текстов.
    # Относительные ссылки вида `../../MODULE_API.md` проход НЕ трогает и трогать не должен: в репо
    # они ведут из `module_system/examples/<mod>/` в `module_system/`, в архиве — из `examples/<mod>/`
    # в его корень, то есть верны в обеих раскладках без единой правки.
    # .go — наравне с .md: репо-префикс живёт и в шапках канонов («КАНОН module_system/shared/…»),
    # и в комментариях helper'а. Все вхождения проверены комментарийными, строковых литералов с этим
    # префиксом в дереве нет. Сам build.py в проход НЕ включён СОЗНАТЕЛЬНО: он несёт таблицу замен
    # выше, и проход по нему схлопнул бы её в `.replace("build.py", "build.py")` — его собственные
    # команды приведены к префикс-независимой форме в докстроке, а не постобработкой.
    #
    # Второе правило того же прохода — переводы строк в LF, и оно шире: касается ВСЕХ текстовых,
    # включая сам build.py. Причина конкретная, не косметика: у build.py шебанг
    # `#!/usr/bin/env python3`, и под CRLF запуск `./build.py` на Linux/macOS падает с
    # `python3\r: No such file or directory`. Архив собирается на трёх ОС, LF корректен на всех,
    # тогда как CRLF ломает ровно ту, на которой автор скорее всего и будет собирать.
    # ⚠ И ПОЭТОМУ ЖЕ проход стоит ПОСЛЕДНИМ — ниже всех записей в стейдж, прямо перед упаковкой.
    # Стоя здесь, он не видел бы файлы, которые генерятся после него (README архива и образец
    # манифеста), и они уезжали бы с CRLF — та же дыра «мимо общего правила», только по позиции,
    # а не по перечню.
    TEXT_SUFFIXES = (".md", ".go", ".py", ".json", ".mod", ".sum")

    def _normalize_stage_text():
        for f in sorted(stage.rglob("*")):
            if not f.is_file() or f.suffix not in TEXT_SUFFIXES:
                continue
            text = f.read_text(encoding="utf-8")
            if f.suffix in (".md", ".go"):
                text = _repo_paths_to_archive(text)
            # Пишем БАЙТАМИ: write_text на Windows вернул бы CRLF обратно при трансляции переводов.
            f.write_bytes(text.replace("\r\n", "\n").encode("utf-8"))

    # Образец манифеста авто-обновления — чтобы форма была видна ДО первой сборки. Реальный
    # (с подставленной версией и перечнем собранных таргетов) генерит `--bundle`.
    #
    # ⛔ Цели перечисляются по КАНОНИЧЕСКИМ спискам (`android_abi_list()` / `DESKTOP_OSES`), а не
    # подмножеством из головы. Образец — это форма, которую автор копирует в реальный манифест, а
    # манифест без бандла под ABI устройства платформа отвергает ЦЕЛИКОМ (MODULE_API §2.5): урезанный
    # образец тихо оставляет часть устройств без обновления, и узнают об этом они, а не автор. Тот же
    # инвариант `cmd_bundle` уже держит отказом на неполном наборе ABI — образец обязан ему не
    # противоречить. Живой случай: сторонний модуль скопировал прежнюю форму (один ABI + две
    # desktop-цели) при пяти реально выложенных бандлах.
    example_manifest = {
        "version": vname,
        "android": {abi: f"https://<host>/{mod}-android-{abi}.zip" for abi in android_abi_list()},
        "desktop": {f"{osname}_amd64": f"https://<host>/{mod}-{osname}_amd64.zip"
                    for osname in DESKTOP_OSES},
        "changelog": "что нового в этой версии",
    }
    (stage / "antinet-module.example.json").write_text(
        json.dumps(example_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (stage / "README.md").write_text(gen_archive_readme(mod), encoding="utf-8")
    _normalize_stage_text()          # последним: стейдж полностью собран, мимо прохода не уедет ничего
    zpath = arch / f"{mod}-module-v{vname}.zip"
    if zpath.exists():
        zpath.unlink()
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(stage.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(arch).as_posix())
    ok(f"[{mod}] архив для автора → {zpath.relative_to(REPO)}  ({zpath.stat().st_size // 1024} КБ)")
    info(f"  автор: распаковать → cd {mod}-module → python build.py --module {mod} --os all")
    return True


def _zip_flat(src_dir, zpath):
    """ПЛОСКИЙ ZIP каталога (module.json + артефакт в корне архива, §2.5) — ровно то, что хост
    распаковывает в `files/modules/<id>/` (Android) / каталог модуля (Desktop)."""
    import zipfile
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(src_dir.iterdir()):
            if f.is_file():
                z.write(f, f.name)


def _bundle_target_mismatch(bundle_dir, expected):
    """Проверяет ПОДПИСЬ бандла перед упаковкой: `bundleTarget` в его `module.json` обязан совпасть
    с ключом, под которым бандл уедет в манифест (`android[<abi>]` / `desktop[<os>_<arch>]`).
    Возвращает текст расхождения либо None.

    Зачем при публикации, а не только на устройстве: перепутанный бандл ставится молча «успешно» —
    хост распакует его, не найдёт годного артефакта и откатится, а автор увидит это только в чужом
    баг-репорте. Здесь же расхождение стоит между сборкой и выкладкой, где ещё дёшево.
    Проверяется РЯДОМ с упаковкой (а не в `_zip_flat`) намеренно: ожидаемый ключ известен только
    вызывающему, и отказ обязан отменить ВЕСЬ релиз, а не пропустить один бандл."""
    jp = bundle_dir / "module.json"
    try:
        got = json.loads(jp.read_text(encoding="utf-8")).get("bundleTarget", "")
    except (OSError, ValueError) as e:
        return f"{jp} не читается: {e}"
    if not got:
        # Старый бандл, собранный до появления поля. Пересборка дешевле догадок о его арке.
        return f"{jp}: нет bundleTarget — пересобери модуль этим build.py"
    if got != expected:
        return f"{jp}: bundleTarget={got}, а бандл кладётся под ключ {expected}"
    return None


def cmd_bundle(mod):
    """Release-артефакты для публикации (§2.5): плоский ZIP каждого собранного `dist/android/<abi>/`
    и `dist/desktop/<os>_<arch>/` + скелет манифеста авто-обновления `antinet-module.json`
    (`version` из module.json, URL'ы — плейсхолдеры для автора) → `dist-release/`.

    ⚠ Форма манифеста ЕДИНАЯ для обеих платформ и совпадает с тем, что реально читают клиенты:
    ОДНА человекочитаемая `version` («1.3.7») + карта «архитектура → URL бандла» на каждый backend
    (`android{abi}` / `desktop{os_arch}`). Никаких `apkUrl`/`soUrl`/`versionCode` — форма ровно одна,
    и генерирует её этот же скрипт, поэтому разъехаться с читателем ей нечем."""
    m = MODULES[mod]
    android_root = REPO / m["root"] / "dist" / "android"
    desktop_root = REPO / m["root"] / "dist" / "desktop"
    rel = REPO / m["root"] / "dist-release"
    rel.mkdir(parents=True, exist_ok=True)

    # ⛔ ПОДПИСИ ПРОВЕРЯЮТСЯ ВСЕ ДО ЕДИНОГО ЗИПА. Проверка «по ходу упаковки» оставляла бы
    # dist-release наполовину записанным: часть архивов новая, часть от прошлого релиза, а автор
    # видит каталог, который выглядит готовым. Отказ обязан не оставлять следов.
    to_zip = []   # (каталог, ключ манифеста)
    if android_root.exists():
        for abi in android_abi_list():
            abi_dir = android_root / abi
            if abi_dir.is_dir() and (abi_dir / m["helper"]).is_file() and (abi_dir / "module.json").is_file():
                to_zip.append((abi_dir, abi))
    if desktop_root.exists():
        to_zip += [(d, d.name) for d in sorted(desktop_root.iterdir()) if d.is_dir()]
    for bdir, key in to_zip:
        if bad := _bundle_target_mismatch(bdir, key):
            err(f"[{mod}] {bad} — релиз не собран, dist-release не тронут"); return False

    android_bundles = {}
    if android_root.exists():
        # ⛔ Идём по КАНОНИЧЕСКОМУ списку ABI, а не по `iterdir()`. Любой посторонний каталог в
        # `dist/android/` (временный, недособранный, чужой) иначе уезжает в релиз как «ABI» — и в
        # манифест авто-обновления вписывается ключ, которого у Android не существует.
        for abi in android_abi_list():
            abi_dir = android_root / abi
            # ABI считается собранным только если есть И .so, И дескриптор: голая библиотека без
            # module.json на устройстве не откроется (discover её не увидит).
            if not abi_dir.is_dir() or not (abi_dir / m["helper"]).is_file() \
                    or not (abi_dir / "module.json").is_file():
                continue
            zpath = rel / f"{mod}-android-{abi}.zip"
            _zip_flat(abi_dir, zpath)
            android_bundles[abi] = f"https://<host>/{mod}-android-{abi}.zip"
            ok(f"[{mod}] android-бандл → {zpath.relative_to(REPO)}")

        # ⛔ НЕПОЛНЫЙ НАБОР ABI — ОТКАЗ, а не тихий частичный релиз. Бандлы уходят в
        # авто-обновление: недостающий ABI значит, что часть устройств получит СТАРУЮ версию
        # модуля (или не получит ничего), и узнают об этом они, а не мы. Живой случай: собран был
        # только `arm64-v8a`, а в релиз уехали три бандла с `.so` суточной давности — сборщик
        # отчитался успехом, потому что честно упаковал то, что нашёл.
        missing = [x for x in android_abi_list() if x not in android_bundles]
        if missing:
            err(f"[{mod}] в dist/android нет ABI: {', '.join(missing)} — бандл был бы неполным.")
            err(f"  собери их: python build.py --os android --abis all --module {mod}")
            return False

    bundles = {}
    if desktop_root.exists():
        for osarch_dir in sorted(desktop_root.iterdir()):
            if not osarch_dir.is_dir():
                continue
            osarch = osarch_dir.name  # windows_amd64 / linux_amd64 / ...
            zpath = rel / f"{mod}-{osarch}.zip"
            _zip_flat(osarch_dir, zpath)
            bundles[osarch] = f"https://<host>/{mod}-{osarch}.zip"
            ok(f"[{mod}] desktop-бандл → {zpath.relative_to(REPO)}")

    if not android_bundles and not bundles:
        info(f"[{mod}] dist/ пуст — сперва `python build.py --module {mod} --os all`")
    manifest = {
        "version": read_module_version(m),
        "android": android_bundles,
        "desktop": bundles,
        "changelog": "что нового в этой версии",
    }
    mpath = rel / "antinet-module.json"
    mpath.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    ok(f"[{mod}] скелет манифеста → {mpath.relative_to(REPO)}  (заполни URL'ы, залей, пропиши updateUrl)")
    return True


HELP_EPILOG = """
ЧТО ЧЕМ СОБИРАЕТСЯ
  desktop-helper (windows/linux/darwin)  Go. И всё: CGO_ENABLED=0, то есть кросс-компиляция
                                         с ЛЮБОГО хоста на ЛЮБУЮ ОС без C-тулчейна.
  android-helper (.so, c-shared)         Go + Android NDK. Тоже кросс с любого хоста.
                                         NDK ищется в ANDROID_NDK_HOME → ANDROID_NDK_ROOT →
                                         ANDROID_HOME/ndk/<последняя> → ANDROID_HOME/ndk-bundle.
  actionBinary  ⛔ ЛЕГАСИ            UI-действия рисует КЛИЕНТ (Android ModuleActionActivity,
                                         Desktop antinet-action), модуль присылает лишь
                                         декларативное правило ACTION_REQUIRED. Новым модулям
                                         это поле объявлять НЕ надо, и C-тулчейн им не нужен.
                                         Поддержка оставлена только для сторонних модулей,
                                         опубликованных до появления хостового рендерера.

  Gradle / Android SDK / AGP НЕ нужны ни для чего: модуль — файл, а не приложение.
  C-компилятор — тоже: helper'ы собираются с CGO_ENABLED=0.
  `--doctor` проверит хост и скажет, чего не хватает и как поставить.

ПРИМЕРЫ
  python build.py --doctor --os all              что установлено, чего нет, как поставить
  python build.py                                полностью интерактивно
  python build.py --os linux   --module echo     helper под Linux (хост-арх)
  python build.py --os windows --module echo --arch amd64
  python build.py --os android --module echo --abis arm64-v8a,armeabi-v7a
  python build.py --os all     --module echo -y  android + windows + linux + darwin
  python build.py --package --module echo        самодостаточный архив автору → dist-archive/
  python build.py --bundle  --module echo        release-бандлы + манифест → dist-release/

ГДЕ ОКАЖЕТСЯ РЕЗУЛЬТАТ
  examples/<module>/dist/android/<abi>/lib<name>.so   + module.json рядом
  examples/<module>/dist/desktop/<os>_<arch>/<bin>    + module.json рядом
"""


def main():
    ap = argparse.ArgumentParser(
        description="Единый сборщик helper-бинарей протокол-модулей AntiNet (MODULE_API §4–§5).",
        epilog=HELP_EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--os", help=f"целевая ОС: {ALL_OSES} | all (android+desktop)")
    ap.add_argument("--module", help=f"модуль: {list(MODULES)}")
    ap.add_argument("--arch", default="amd64", help="GOARCH для desktop (amd64|arm64|386|arm; default amd64)")
    # ⛔ Дефолт `None`, а не `arm64-v8a`: он резолвится ПО ЦЕЛИ (см. ниже). При `--os all` человек
    # просит собрать ВСЁ, и молча получить один ABI из четырёх — ровно та ловушка, из-за которой
    # в release-бандлы уехали три устаревших `.so`. Явный `--abis` по-прежнему главнее.
    ap.add_argument("--abis", default=None,
                    help="ABI для android (через запятую; all = все; default arm64-v8a, "
                         "а при --os all — все)")
    ap.add_argument("--api", type=int, default=26, help="Android API level для NDK clang (default 26)")
    ap.add_argument("-y", "--yes", action="store_true", help="не задавать вопросов (всё из флагов/дефолтов)")
    ap.add_argument("--doctor", action="store_true",
                    help="проверить тулчейн (Go/NDK/C-компилятор) и напечатать, чего не хватает и как поставить")
    ap.add_argument("--package", action="store_true",
                    help="собрать самодостаточный архив модуля для автора → dist-archive/<mod>-module-v<ver>.zip")
    ap.add_argument("--bundle", action="store_true",
                    help="release-бандлы (плоский ZIP каждого dist/<target>/) + скелет манифеста авто-обновления → dist-release/")
    a = ap.parse_args()

    # doctor — самостоятельная команда: ничего не собирает, только смотрит на хост.
    if a.doctor:
        targets = list(ALL_OSES) if a.os in (None, "all") else [a.os]
        return 0 if cmd_doctor(targets, a.module) else 1

    # package / bundle — не требуют Go (только копирование/zip); резолвим модуль и выходим.
    if a.package or a.bundle:
        mod = a.module
        if not mod and not a.yes:
            mod = ask_choice("Модуль", list(MODULES), next(iter(MODULES)))
        if mod not in MODULES:
            err(f"Неизвестный модуль: {mod}. Допустимо: {list(MODULES)}"); return 2
        okall = True
        if a.package:
            okall = cmd_package(mod) and okall
        if a.bundle:
            okall = cmd_bundle(mod) and okall
        return 0 if okall else 1

    interactive = not a.yes
    print(c("=== AntiNet module builder (any OS) ===", "1;36"))

    # модуль
    mod = a.module
    if not mod and interactive:
        mod = ask_choice("Модуль", list(MODULES), next(iter(MODULES)))
    if mod not in MODULES:
        err(f"Неизвестный модуль: {mod}. Допустимо: {list(MODULES)}"); return 2

    # ОС
    target = a.os
    if not target and interactive:
        target = ask_choice("Целевая ОС", ALL_OSES + ["all"], "linux")
    if target not in ALL_OSES + ["all"]:
        err(f"Неизвестная ОС: {target}. Допустимо: {ALL_OSES + ['all']}"); return 2

    # desktop arch (вопрос ТОЛЬКО для нативных desktop-ОС)
    arch = a.arch
    if target in DESKTOP_OSES and interactive:
        arch = ask("GOARCH (desktop)", a.arch)

    if target == "all":
        targets = list(ALL_OSES)
    else:
        targets = [target]

    # Резолв ABI ПО ЦЕЛИ (см. доккоммент ключа): явный `--abis` главнее всего; `--os all` значит
    # «собери всё», то есть и все ABI; одиночная цель сохраняет прежний дешёвый дефолт.
    abis = a.abis
    if abis is None:
        abis = "all" if target == "all" else "arm64-v8a"
        if target == "all":
            info("--os all → ABI: все (явный --abis перекрывает)")

    # ⚠ Префлайт ДО первой сборки, а не после падения: `go build упал (код 1)` не говорит автору
    # стороннего модуля НИЧЕГО о том, чего не хватает. Здесь же — что именно и команда установки
    # под его хост-ОС. Интерактивный режим оставляет шанс дать путь к go руками (как было раньше).
    problems = check_toolchain(targets, mod, abis, a.api)
    if problems:
        go_missing = any("Go" in w for w, _ in problems)
        if go_missing and interactive:
            manual = ask("Путь к go (не найден в PATH; пусто — выйти)")
            if manual and Path(manual).exists():
                os.environ["PATH"] = str(Path(manual).parent) + os.pathsep + os.environ.get("PATH", "")
                problems = check_toolchain(targets, mod, abis, a.api)
        if problems:
            report_toolchain(problems)
            return 2

    go = find_go()
    print()
    info(f"Модуль '{mod}' → {targets}" + (f" (desktop arch={arch})" if any(t in DESKTOP_OSES for t in targets) else ""))
    print()

    fails = []
    for t in targets:
        if t == "android":
            if not build_android(mod, abis, a.api):
                fails.append("android")
        else:
            if not build_desktop(go, mod, t, arch):
                fails.append(f"{t}_{arch}")
        print()

    if fails:
        err(f"Не собрались цели: {fails}"); return 1
    ok(f"Готово. Модуль '{mod}' собран под: {targets}.")
    if "android" in targets:
        adir = REPO / MODULES[mod]['root'] / 'dist' / 'android'
        ok(f"Android .so + module.json: {adir}/<abi>/ — хост грузит .so `dlopen`'ом в слот-процесс.")
    if any(t in DESKTOP_OSES for t in targets):
        ok(f"Desktop-бинарь(и): {REPO / MODULES[mod]['root'] / 'dist' / 'desktop'} — Desktop-хост форкает его суб-процессом.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
