// SPDX-License-Identifier: MIT

//go:build !android && !linux

package main

// КАНОН shared/lifecycle — `dieWithParent` для десктопа БЕЗ PDEATHSIG
// (GOOS=windows/darwin). Полное обоснование канона — в шапке `lifecycle_android.go`,
// содержательное — в `lifecycle_dieparent_linux.go`.

// dieWithParent — no-op: аналога `PR_SET_PDEATHSIG` тут нет (Windows не имеет его в принципе,
// в darwin он не реализован). Осиротевшего helper'а на этих ОС ловит ТОЛЬКО стартовый свип хоста
// `CleanupOrphanHelpers` (`modulemanager.pas:647-720`, `taskkill /F /IM`) — то есть на старте
// следующего бэкенда, а не в момент смерти. Это осознанно оставшийся разрыв: закрыть его нечем,
// кроме job-объектов Windows, а они меняют модель запуска целиком.
func dieWithParent() {}
