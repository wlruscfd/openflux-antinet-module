// SPDX-License-Identifier: MIT

//go:build android

package main

/*
#include <stdlib.h>
*/
import "C"

import "unsafe"

// КАНОН shared/entry — ANDROID-вход модуля. Инжектируется build.py в main-пакет
// КАЖДОГО модуля (гейта нет). Парная десктопная половина — entry_native.go.
//
// ⛔ Своей копии не заводи: набор и сигнатуры экспортов — часть C-ABI, по которому слот-процесс
// зовёт модуль через dlsym. Разойтись с ним можно молча (шим просто не найдёт символ), и увидишь
// это только на устройстве.
//
// На Android модуль — не процесс, а БИБЛИОТЕКА: скачанный файл запустить нельзя (W^X с API 29+
// бьёт по execve любого writable-файла), а dlopen под запрет не попадает (живо проверено на
// устройстве). Поэтому сборка идёт `-buildmode=c-shared`, а слот AntiNet грузит .so C-шимом и
// зовёт экспорты ниже.
//
// ОТ МОДУЛЯ НУЖНЫ ДВЕ ФУНКЦИИ, и больше ничего:
//
//	func realMain(configContent, resolversPath, profileDir, protectPath string, listenFd int) int
//	func moduleCall(verb, arg string) string
//
// c-shared требует объявленного main() у package main (рантайм ссылается на runtime.main_main·f при
// линковке), хотя НИКОГДА его не вызывает: точка входа здесь — antinet_module_run. Тело пустое.
func main() {}

// antinet_module_run — единственная обязательная точка входа (MODULE_API §2.3). Блокирует, как main().
//
//	configContent — СОДЕРЖИМОЕ конфига, а не путь: секреты (SOCKS_PASS, апстримный секрет внутри
//	                LINK=) не должны касаться диска (§3).
//	listenFd      — готовый слушающий SOCKS5-сокет: им владеет ХОСТ (§2.6), сокет переживает
//	                смерть/подмену модуля, а порт хост знает сразу и авторитетно.
//
//export antinet_module_run
func antinet_module_run(configContent, resolversPath, profileDir, protectPath *C.char, listenFd C.int) C.int {
	return C.int(realMain(
		C.GoString(configContent),
		C.GoString(resolversPath),
		C.GoString(profileDir),
		C.GoString(protectPath),
		int(listenFd),
	))
}

// antinet_module_event — событие от хоста (§2.8): "handover" либо `ACTION_RESULT|<id>|<payload>`.
//
// Заменяет SIGUSR1, который в слот-процессе НЕДЕТЕРМИНИРОВАН: ART блокирует его на своих потоках,
// Go-потоки создаются от ART-потоков и НАСЛЕДУЮТ маску, а process-directed сигнал ядро отдаёт
// единственному незаблокированному потоку — ART'овскому «Signal», где Go форвардит его прежнему
// обработчику вместо signal.Notify. Прямой вызов через dlsym от масок и версии ART не зависит.
//
//export antinet_module_event
func antinet_module_event(event *C.char) C.int {
	handleHostEvent(C.GoString(event))
	return 0
}

// antinet_module_call — parse-only сабкоманды (§2.2: summarize/normalize/canping). На desktop их
// обслуживает argv, но .so запустить нельзя — это библиотека, не процесс. Слот зовёт этот экспорт
// напрямую; тело общее с desktop-формой (`moduleCall` модуля).
//
// Возврат — malloc'нутая C-строка; освобождает ВЫЗЫВАЮЩИЙ через antinet_module_free.
//
//export antinet_module_call
func antinet_module_call(verb, arg *C.char) *C.char {
	return C.CString(moduleCall(C.GoString(verb), C.GoString(arg)))
}

// antinet_module_free — парная освобождалка для строк из antinet_module_call. Отдельный экспорт, а
// не free() на стороне шима: память malloc'ена рантаймом ЭТОЙ .so, освобождать её обязан тот же
// аллокатор.
//
//export antinet_module_free
func antinet_module_free(p *C.char) {
	C.free(unsafe.Pointer(p))
}
