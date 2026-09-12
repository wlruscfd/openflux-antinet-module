// SPDX-License-Identifier: MIT

//go:build linux && !android

package main

// КАНОН shared/lifecycle — `dieWithParent` для Desktop-Linux.
// Полное обоснование канона — в шапке `lifecycle_android.go`.
//
// ⚠ `&& !android` обязателен: GOOS=android удовлетворяет и тегу `linux`, а суффикс имени файла
// `_linux.go` даёт то же неявное ограничение. Без явного отрицания этот файл собрался бы и под
// Android, где `dieWithParent` уже определён в `lifecycle_android.go` → redeclared.

import "golang.org/x/sys/unix"

// dieWithParent — умереть вместе с родителем (backend AntiNet): не оставить осиротевший helper.
//
// ⛔ ЗАЧЕМ ЗДЕСЬ, ЕСЛИ ХОСТ И ТАК УБИВАЕТ HELPER'А. Убивает — но только когда хост ЖИВ и успевает
// это сделать (`StopAll`). Резкая смерть бэкенда (краш, SIGKILL, эскалация `Application.Terminate`
// у amGui-оркестратора) обходит весь этот путь, и helper остаётся жить. Без PDEATHSIG такого
// сироту ловит ТОЛЬКО стартовый свип `CleanupOrphanHelpers` (`modulemanager.pas`) — то есть на
// старте СЛЕДУЮЩЕГО бэкенда, а всё время простоя сирота работает. Цена этого измерена в проде:
// осиротевший helper держит свой `127.0.0.1:<port>`, новый launch падает `bind: address already
// in use`, дальше вечный retry коннекта.
//
// PDEATHSIG закрывает окно на уровне ядра: сигнал приходит В МОМЕНТ смерти родителя, не завися ни
// от кода хоста, ни от того, успел ли он что-нибудь выполнить. Свип при этом НЕ снимается — он
// остаётся единственной защитой на Windows (PDEATHSIG там не существует) и страховкой на Linux
// для helper'ов, переживших смену модели/сборки.
//
// Симметрия с Android: там роль этой функции играет самореап слота в
// `ModuleHostService.onDestroy` (PDEATHSIG под Android бесполезен — родитель слот-процесса zygote,
// он не умирает). Инвариант «сирота не переживает хозяина» теперь держится на ОБЕИХ платформах
// мгновенно, а не отложенно.
//
// Best-effort: ошибка проглатывается — на ядре/контейнере, где prctl запрещён, это просто no-op,
// а не повод не стартовать (та же политика, что у android-варианта).
func dieWithParent() {
	_ = unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL), 0, 0, 0)
}
