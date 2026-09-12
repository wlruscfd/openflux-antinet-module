#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: MIT
"""
build-module.py — собрать helper-бинарь протокол-модуля AntiNet (см. MODULE_API.md §5).

Кросс-компилит Go data-plane модуля в разделяемую библиотеку (`-buildmode=c-shared`) на каждый
ABI через NDK clang и кладёт в <out>/<abi>/lib<name>.so. Скачанный файл на Android нельзя
`execve` (W^X, API 29+), но можно `dlopen` — AntiNet грузит .so в свой слот-процесс.

Windows-first (но Python → кроссплатформенно: Linux/macOS тоже). Интерактивен: чего не
передали флагами — спросит. Примеры:

  python tools/build-module.py                       # полностью интерактивно
  python tools/build-module.py --go-dir modulemasterdns/native/MasterDnsVPN \\
       --helper libmdvpnhelper.so --abis arm64-v8a

Требует: Go — версию диктует `go`-директива go.mod собираемого модуля (`build.py --doctor` сверит
её с установленной), Android NDK (ANDROID_NDK_HOME / ANDROID_HOME/ndk/<ver>).
"""
import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# Windows-консоль часто cp1251/cp866 → UnicodeEncodeError на ✓/кириллице. Форсим UTF-8 вывод.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ABI → (GOARCH, GOARM|None, clang-prefix). clang = "<prefix><api>-clang" (+ .cmd на Windows).
ABI_MAP = {
    "arm64-v8a":   ("arm64", None, "aarch64-linux-android"),
    "armeabi-v7a": ("arm",   "7",  "armv7a-linux-androideabi"),
    "x86":         ("386",   None, "i686-linux-android"),
    "x86_64":      ("amd64", None, "x86_64-linux-android"),
}
IS_WIN = os.name == "nt"


def c(txt, code):  # цветной вывод (no-op если не TTY)
    return f"\033[{code}m{txt}\033[0m" if sys.stdout.isatty() else txt


def info(m):  print(c("• ", "36") + m)
def ok(m):    print(c("✓ ", "32") + m)
def warn(m):  print(c("⚠ ", "33") + m)
def err(m):   print(c("✗ ", "31") + m, file=sys.stderr)


def ask(prompt, default=None):
    sfx = f" [{default}]" if default else ""
    try:
        v = input(c("? ", "35") + prompt + sfx + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        print(); sys.exit(1)
    return v or (default or "")


def find_go():
    g = shutil.which("go")
    if g:
        return g
    cand = Path(os.environ.get("GOROOT", "")) / "bin" / ("go.exe" if IS_WIN else "go")
    return str(cand) if cand.exists() else None


def find_ndk():
    """ANDROID_NDK_HOME → ANDROID_NDK_ROOT → ANDROID_HOME/ndk/<latest> → ANDROID_HOME/ndk-bundle."""
    for env in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        p = os.environ.get(env)
        if p and Path(p).is_dir():
            return Path(p)
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk:
        ndk_root = Path(sdk) / "ndk"
        if ndk_root.is_dir():
            vers = sorted([d for d in ndk_root.iterdir() if d.is_dir()], key=lambda d: d.name)
            if vers:
                return vers[-1]  # самая свежая версия
        bundle = Path(sdk) / "ndk-bundle"
        if bundle.is_dir():
            return bundle
    return None


def ndk_bin(ndk: Path) -> Path:
    host = {"Windows": "windows-x86_64", "Linux": "linux-x86_64", "Darwin": "darwin-x86_64"}.get(platform.system())
    b = ndk / "toolchains" / "llvm" / "prebuilt" / host / "bin"
    if not b.is_dir():
        # fallback: поискать любой prebuilt/*/bin
        pre = ndk / "toolchains" / "llvm" / "prebuilt"
        if pre.is_dir():
            for d in pre.iterdir():
                if (d / "bin").is_dir():
                    return d / "bin"
    return b


def clang_for(ndk_bin_dir: Path, prefix: str, api: int) -> Path:
    name = f"{prefix}{api}-clang" + (".cmd" if IS_WIN else "")
    return ndk_bin_dir / name


def build_abi(go: str, go_dir: Path, go_pkg: str, abi: str, api: int,
              ndk_bin_dir: Path, out_so: Path, ldflags: str = "",
              buildmode: str = "c-shared") -> bool:
    goarch, goarm, prefix = ABI_MAP[abi]
    cc = clang_for(ndk_bin_dir, prefix, api)
    if not cc.exists():
        err(f"[{abi}] нет clang: {cc} (проверь NDK/API)")
        return False
    out_so.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env.update(GOOS="android", GOARCH=goarch, CGO_ENABLED="1", CC=str(cc))
    if goarm:
        env["GOARM"] = goarm
    # ⚠ `c-shared`, НЕ `pie`. Скачанный файл на Android НЕЛЬЗЯ запустить (`execve` бьётся
    # о W^X с API 29+), но МОЖНО загрузить — `dlopen` под этот запрет не попадает (живо проверено).
    # Поэтому Android-артефакт модуля — не
    # исполняемый PIE-бинарь, а разделяемая библиотека с единственным C-ABI-экспортом
    # `antinet_module_run`, которую слот-процесс грузит шимом. Desktop остаётся на реальном exec
    # (там W^X нет) — там сборка идёт другим путём, этот скрипт про Android.
    cmd = [go, "build", f"-buildmode={buildmode}", "-trimpath"]
    # -ldflags (default -checklinkname=0): нужно модулям с //go:linkname-зависимостями (qWDTT тянет
    # github.com/wlynxg/anet → net.zoneCache; Go 1.23+ иначе валит линковку "invalid reference").
    # Безвреден для модулей без linkname (echo) — проверять нечего. Author может переопределить --ldflags.
    if ldflags:
        cmd.append(f"-ldflags={ldflags}")
    cmd += ["-o", str(out_so), go_pkg]
    info(f"[{abi}] {' '.join(cmd)}  (GOARCH={goarch} CC={cc.name})")
    r = subprocess.run(cmd, cwd=str(go_dir), env=env)
    if r.returncode != 0:
        err(f"[{abi}] go build упал (код {r.returncode})")
        return False
    sz = out_so.stat().st_size if out_so.exists() else 0
    ok(f"[{abi}] → {out_so}  ({sz} байт)")
    return True


def main():
    ap = argparse.ArgumentParser(description="Собрать helper-бинарь протокол-модуля AntiNet (MODULE_API.md §5).")
    ap.add_argument("--go-dir", help="каталог Go-модуля helper'а (где go.mod)")
    ap.add_argument("--go-pkg", default="./cmd/helper", help="Go-пакет для сборки (default ./cmd/helper)")
    ap.add_argument("--ldflags", default="-checklinkname=0",
                    help="go build -ldflags (default -checklinkname=0 — нужно для //go:linkname-зависимостей "
                         "типа anet/net.zoneCache; безвреден без них. Пусто = без ldflags)")
    ap.add_argument("--out-jnilibs", dest="out_dir",
                    help="каталог выдачи (default <go-dir>/../../dist/android); внутри — <abi>/lib*.so")
    ap.add_argument("--helper", help="имя выходного бинаря, lib*.so (напр. libmyhelper.so)")
    ap.add_argument("--abis", default="arm64-v8a", help="ABI через запятую (default arm64-v8a; all = все)")
    ap.add_argument("--api", type=int, default=26, help="Android API level для NDK clang (default 26)")
    ap.add_argument("--ndk", help="путь к NDK (default из ANDROID_NDK_HOME / ANDROID_HOME/ndk)")
    ap.add_argument("-y", "--yes", action="store_true", help="не задавать вопросов (все из флагов/дефолтов)")
    a = ap.parse_args()

    interactive = not a.yes
    print(c("=== AntiNet module helper builder ===", "1;36"))

    # Go
    go = find_go()
    if not go:
        if interactive: go = ask("Путь к go (не найден в PATH)")
        if not go or not Path(go).exists():
            err("Go не найден. Установи Go или укажи путь."); return 2
    ok(f"Go: {go}")

    # NDK
    ndk = Path(a.ndk) if a.ndk else find_ndk()
    if not ndk or not ndk.is_dir():
        if interactive: ndk = Path(ask("Путь к Android NDK (не найден)"))
    if not ndk or not ndk.is_dir():
        err("NDK не найден. Задай ANDROID_NDK_HOME или --ndk."); return 2
    nbin = ndk_bin(ndk)
    if not nbin.is_dir():
        err(f"NDK toolchain bin не найден: {nbin}"); return 2
    ok(f"NDK: {ndk}  (bin: {nbin.name})")

    # Go-каталог
    go_dir = a.go_dir or (ask("Каталог Go-модуля helper'а (где go.mod)") if interactive else "")
    go_dir = Path(go_dir).resolve() if go_dir else None
    if not go_dir or not (go_dir / "go.mod").exists():
        err(f"go.mod не найден в {go_dir}. Это каталог Go-модуля helper'а?"); return 2
    ok(f"Go-модуль: {go_dir}")

    go_pkg = a.go_pkg
    if interactive:
        go_pkg = ask("Go-пакет для сборки helper'а", a.go_pkg)

    # имя бинаря
    helper = a.helper or (ask("Имя выходного бинаря (lib*.so)", "libhelper.so") if interactive else "libhelper.so")
    if not (helper.startswith("lib") and helper.endswith(".so")):
        warn(f"'{helper}' не lib*.so — Android может не распаковать его в nativeLibraryDir (нужен useLegacyPackaging). "
             "Рекомендуется имя вида libNAME.so.")
        if interactive and ask("Продолжить всё равно? (y/N)", "N").lower() != "y":
            return 1

    # каталог выдачи: <out>/<abi>/lib*.so (рядом build.py кладёт module.json — §2.1)
    out_jnilibs = a.out_dir
    if not out_jnilibs:
        guess = (go_dir / ".." / ".." / "dist" / "android").resolve()
        out_jnilibs = ask("Каталог выдачи (dist/android)", str(guess)) if interactive else str(guess)
    out_jnilibs = Path(out_jnilibs).resolve()
    ok(f"выдача: {out_jnilibs}")

    # ABIs
    abis_arg = a.abis
    if interactive:
        abis_arg = ask("ABI (через запятую; all = все)", a.abis)
    abis = list(ABI_MAP.keys()) if abis_arg.strip() == "all" else [x.strip() for x in abis_arg.split(",") if x.strip()]
    bad = [x for x in abis if x not in ABI_MAP]
    if bad:
        err(f"Неизвестные ABI: {bad}. Допустимые: {list(ABI_MAP)}"); return 2

    api = a.api
    print()
    info(f"Сборка '{helper}' для {abis} (API {api}) из {go_pkg}"
         + (f" [ldflags={a.ldflags}]" if a.ldflags else "") + " …")
    print()

    fails = []
    for abi in abis:
        out_so = out_jnilibs / abi / helper
        if not build_abi(go, go_dir, go_pkg, abi, api, nbin, out_so, a.ldflags):
            fails.append(abi)
        print()

    if fails:
        err(f"Не собрались ABI: {fails}"); return 1
    ok(f"Все ABI собраны → {out_jnilibs}")

    print()
    ok("Готово. Helper-.so — в dist/android/<abi>/ модуля.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
