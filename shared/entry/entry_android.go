// SPDX-License-Identifier: MIT

//go:build android

package main

/*
#include <stdlib.h>
*/
import "C"

import "unsafe"

// shared/entry is the Android entry point, injected by build.py into every module's main package.
// main is never called, but c-shared requires it declared in package main.
func main() {}

// antinet_module_run is the module's one required entry point (MODULE_API §2.3); configContent is the config's content, not a path.
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
