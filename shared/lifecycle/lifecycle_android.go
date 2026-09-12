// SPDX-License-Identifier: MIT

//go:build android

package main

// КАНОН shared/lifecycle — платформенные примитивы ЖИЗНЕННОГО ЦИКЛА helper'а,
// одинаковые для ЛЮБОГО модуля. Инжектируется build.py в main-пакет helper'а ПЕРЕД сборкой и
// удаляется ПОСЛЕ (тот же механизм, что shared/protect и shared/offtun).
//
// Почему канон, а не по копии в каждом модуле: здесь нет НИ ОДНОЙ строчки, зависящей от протокола
// модуля, — это чистая обвязка ОС. Копии такого кода расходятся молча и в мелочах (один вариант
// печатает диагностику в stderr на каждом старте, другой — тихий однострочник), и сборку это не
// ломает: разницу видно только в рантайме.
//
// Модулю остаётся ТОЛЬКО его тонкий protect-адаптер (`dialControl`/`makeProtectControl`/
// `makeProtectFunc` в его собственном `platform_*.go`) — форму хука диктует data-plane библиотека
// модуля, единой она быть не может.

import (
	"os"

	"golang.org/x/sys/unix"
)

// dieWithParent — умереть вместе с родителем (AntiNet): не оставить осиротевший helper после
// смерти VPN-процесса. Best-effort (ошибка проглатывается — на ROM, где prctl запрещён, это просто
// no-op, а не повод не стартовать).
func dieWithParent() {
	_ = unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0)
}

// protectFromOomKill — снизить СОБСТВЕННЫЙ /proc/self/oom_score_adj до -1000 (kernel-минимум,
// «никогда не убивать», уровень init).
//
// Defense-in-depth, а не обязанность модуля: хост-сторона и так держит слот-процесс `BIND_IMPORTANT`
// (MODULE_API §2.3), но между стартом процесса и первой строчкой Go-кода есть окно, которое
// закрывает только self-write. Live-verified на устройстве (adb run-as, тот же UID): запись
// собственного oom_score_adj в любую сторону, включая -1000, разрешена — SELinux её не блокирует.
// Best-effort: где запись запрещена — тихий no-op. Гарантированно уважается kernel-LMK;
// вендор-специфичные killer'ы (Transsion/MIUI/EMUI) могут это поле игнорировать — не панацея.
// Зовётся ОДИН раз на старте: сбрасывать это поле позже нечему.
func protectFromOomKill() {
	_ = os.WriteFile("/proc/self/oom_score_adj", []byte("-1000"), 0o644)
}

// startHostEventReader — на Android событий из stdin нет: модуль здесь БИБЛИОТЕКА в слот-процессе,
// а хост зовёт C-ABI-экспорт `antinet_module_event` напрямую (см. entry_android.go модуля).
// No-op существует, чтобы вызов в общем теле helper'а был ОДИН и тот же на обеих платформах.
func startHostEventReader() {}
