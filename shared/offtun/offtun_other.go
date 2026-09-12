// SPDX-License-Identifier: MIT

//go:build !android && !linux && !windows && !darwin

// Канонический off-TUN socket-protect — заглушка для прочих десктоп-ОС (freebsd/…): специфичного
// механизма нет → no-op (helper дайлит обычным путём, off-TUN на усмотрение sing-box routing).
// Закрывает партицию (linux&&!android / windows / darwin покрыты своими файлами). Инжектируется build.py.
// android сюда НЕ попадает (его off-TUN — SCM_RIGHTS в platform_android.go модуля; build.py инжектит
// offtun_* ТОЛЬКО в desktop-сборку). package main.
package main

import "syscall"

func offtunBindControl(network, address string, c syscall.RawConn) error { return nil }

func offtunBindFd(fd int) bool { return true }
