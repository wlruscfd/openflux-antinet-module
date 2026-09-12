// SPDX-License-Identifier: MIT

//go:build android

package main

// КАНОН shared/protect — ADAPTER'Ы protect-хука для ANDROID. Парная десктопная
// половина — `shared/offtun/offtun_adapter.go`, имена и сигнатуры там ТЕ ЖЕ, поэтому общий код
// модуля зовёт их без единого build-тега у себя.
//
// ⛔ Своей копии не заводи. До сведения этот адаптер жил тремя копиями под тремя именами —
// `dialControl` (echo), `makeProtectControl` (qWDTT), `makeProtectFunc` (masterdns), — и
// MODULE_API объяснял это «тремя разными сигнатурами, которые диктует data-plane библиотека». На
// деле сигнатур ДВЕ, а не три: первые две были одной и той же функцией с точностью до имени.
//
// Формы ровно две, потому что столько их бывает у хуков реальных data-plane библиотек:
//
//	dialControl    — форма `net.Dialer.Control` / `net.ListenConfig.Control` (echo, qWDTT, OpenFlux);
//	protectFdFunc  — форма `func(fd int32) bool` (masterdns: `nativeclient.Options.Protect`).
//
// Обе делают одно: отправляют КАЖДЫЙ исходящий fd на protect-сервис AntiNet (SCM_RIGHTS), иначе
// сокет helper'а уходит в НАШ ЖЕ TUN (наш UID внутри туннеля, Husi-pattern) → петля.

import (
	"errors"
	"syscall"
)

// dialControl — protect-хук формы `net.Dialer.Control`.
//
// `protectPath == ""` → nil: TUN не поднят, протектить нечем и незачем (nil-Control для net.Dialer —
// штатный no-op, не паника).
//
// ⏱ `st` (может быть nil) — замер ЭТОГО шага отдельно от самого `connect`. Причина: `Control`
// вызывается СИНХРОННО внутри `Dial` до подключения, поэтому его стоимость неотличима от сетевой,
// если не мерить отдельно. Живой замер: медиана дозвона 64мс при max 1738мс к ТОМУ ЖЕ IP и
// lookupElapsed=0 — весь разброс сидел именно здесь. Модулю, у которого своя разбивка замеров,
// достаточно передать nil.
func dialControl(protectPath string, st *protectStat) func(network, address string, c syscall.RawConn) error {
	if protectPath == "" {
		return nil
	}
	return func(_, _ string, rc syscall.RawConn) error {
		var perr error
		if err := rc.Control(func(fd uintptr) {
			if ok, _ := protectViaService(protectPath, int(fd), st); !ok {
				perr = errors.New("protect failed")
			}
		}); err != nil {
			return err
		}
		return perr
	}
}

// protectFdFunc — protect-хук формы `func(fd int32) bool` (её хочет, например,
// `nativeclient.Options.Protect` у masterdns). `protectPath == ""` → nil, как и выше.
func protectFdFunc(protectPath string) func(int32) bool {
	if protectPath == "" {
		return nil
	}
	return func(fd int32) bool {
		ok, _ := protectViaService(protectPath, int(fd), nil)
		return ok
	}
}
