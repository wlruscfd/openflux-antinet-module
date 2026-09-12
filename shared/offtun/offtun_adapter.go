// SPDX-License-Identifier: MIT

//go:build !android

package main

// КАНОН shared/offtun — ADAPTER'Ы protect-хука для ДЕСКТОПА (windows/linux/darwin).
// Парная android-половина — `shared/protect/protect_adapter_android.go`; имена и сигнатуры ТЕ ЖЕ,
// поэтому общий код модуля зовёт их без единого build-тега у себя.
//
// ⛔ Своей копии не заводи (обоснование и история трёх разошедшихся копий — в шапке android-половины).
//
// На десктопе изоляция даётся не SCM_RIGHTS-сервисом, а привязкой сокета к ФИЗИЧЕСКОМУ адаптеру
// (Linux SO_BINDTODEVICE / Windows IP_UNICAST_IF / macOS IP_BOUND_IF) — см. offtun_<GOOS>.go рядом.
// `protectPath` здесь не нужен: биндим по интерфейсу, а не через сокет сервиса.
//
// ⚠ Почему этого мало НЕ бывает: обоснования «off-TUN на десктопе даёт sing-box routing
// process_name→direct» не хватает. Оно уводит egress мимо НАШЕГО TUN, но «direct» — это системный
// маршрут по умолчанию, а он может принадлежать ЧУЖОМУ VPN-клиенту (живой случай: адаптер neko-tun
// на dev-машине — модуль честно шёл «напрямую», а в actual ip светился exit чужого туннеля). Плюс
// в proxy-only-режиме нашего TUN нет вовсе, и routing-правило не участвует.

import "syscall"

// dialControl — protect-хук формы `net.Dialer.Control`; на десктопе это канон offtunBindControl.
// Параметры не используются: ни путь protect-сервиса (его тут нет), ни замер (мерить нечего —
// bind локальный и не ходит по сети).
func dialControl(protectPath string, st *protectStat) func(network, address string, c syscall.RawConn) error {
	_ = protectPath
	_ = st
	return offtunBindControl
}

// protectFdFunc — protect-хук формы `func(fd int32) bool`; на десктопе это канон offtunBindFd.
func protectFdFunc(protectPath string) func(int32) bool {
	_ = protectPath
	return func(fd int32) bool { return offtunBindFd(int(fd)) }
}
