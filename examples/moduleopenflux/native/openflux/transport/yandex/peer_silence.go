package yandex

import "time"

// ⚠️ ФАЙЛ МОДУЛЬНЫЙ, НЕ из openflux-server.
//
// Дивергенция AntiNet: сессия может остаться внешне живой после того, как exit-узел исчез из
// документа. Писать по-прежнему успешно (Яндекс отвечает), и read-deadline не срабатывает —
// дедлайн продлевает ЛЮБОЙ входящий кадр, а Яндекс шлёт свои Socket.IO-пинги независимо от
// присутствия второго участника. Ничто в серверном коде такую сессию не замечает: ForceReconnect
// ронял её и звонил обратно в того же молчащего пира, а канал возвращался сам через ~8 минут.
//
// Замерено на устройстве 2026-09-17 15:08:46–15:16: в этом окне только строки "[YDOCS] ->",
// ни одного входящего кадра и ни одной "Keep-alive failed".
//
// Проверка стоит именно в keepAliveLoop, а не в read loop: тик — единственное, что работает по
// расписанию, пока ReadMessage сидит заблокированным, то есть именно он способен заметить
// ОТСУТСТВИЕ. Read loop реагирует только на пришедшие байты, а в том и суть, что их нет.

const peerSilenceFactor = 4

// notePeerMsg отмечает приход кадра от пира. Вызывается из read loop (yandex.go).
func (t *YandexDocsTransport) notePeerMsg() {
	t.lastPeerMsgAtNano.Store(time.Now().UnixNano())
}

// peerSilent истинно, когда от пира не было ни одного кадра дольше окна в peerSilenceFactor
// keep-alive интервалов.
func (t *YandexDocsTransport) peerSilent() bool {
	last := t.lastPeerMsgAtNano.Load()
	if last == 0 {
		// Ещё ничего не слышали: сессия только поднимается, судить не о чем.
		return false
	}
	window := t.GetConfig().KeepAliveInterval * peerSilenceFactor
	if window <= 0 {
		// Keep-alive выключен конфигом — судить не по чему.
		return false
	}
	return time.Since(time.Unix(0, last)) > window
}
