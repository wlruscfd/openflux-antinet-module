package yandex

import "universal-bypass-tool/utils"

// Handover — сеть под транспортом сменилась (событие хоста, MODULE_API §2.8): рвём ЖИВОЙ WebSocket
// и больше ничего.
//
// Отдельным файлом, а не правкой `yandex.go`: тот — дословная копия openflux-server, и апстрим-бамп
// сводится к перезаписи файла. Всё, что принадлежит модулю, а не апстриму, живёт рядом.
//
// Своего пути подъёма здесь нет намеренно: обрыв поднимает read-петля в [YandexDocsTransport.connectToDoc]
// — она уже умеет и переиспользовать очередь записи, и не наращивать backoff после долгой сессии
// (`connectedAt > 15s` → attempt=0). Второй заход отсюда дал бы ДВЕ сессии на один транспорт:
// писателя у `t.session` ровно один, и это та петля.
//
// Молчание при отсутствии сессии — не проглоченная ошибка: транспорт ещё не поднялся, значит
// поднимется уже на новой сети, и рвать нечего.
func (t *YandexDocsTransport) Handover() {
	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()
	if session == nil || session.Conn == nil {
		return
	}
	utils.Debugf("[YDOCS] handover: dropping live session to re-dial on the new network")
	_ = session.Conn.Close()
}
