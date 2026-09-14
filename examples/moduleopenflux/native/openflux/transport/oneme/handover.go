package oneme

import "universal-bypass-tool/utils"

// Handover — сеть под транспортом сменилась (событие хоста, MODULE_API §2.8): просим call-handler
// переустановить звонок своей же петлёй ([CallHandler.signalReconnect] → `reconnectCh`), а не
// поднимаем второй путь подъёма.
//
// Отдельным файлом, а не правкой вендорных `max_*.go`: те — дословные копии openflux-server, и
// апстрим-бамп сводится к перезаписи файлов.
//
// ⚠ Работает это только в роли caller (клиент модуля всегда caller — [startOutgoingCall]); в роли
// receiver тот же `signalReconnect` завершает процесс, и это правильно для exit-node, но здесь
// недостижимо. Нет handler'а (Start ещё не прошёл) — рвать нечего, транспорт поднимется уже на
// новой сети.
func (t *OneMeTransport) Handover() {
	if t.ch == nil {
		return
	}
	utils.Debugf("[MAX] handover: asking the call handler to re-establish on the new network")
	t.ch.signalReconnect()
}
