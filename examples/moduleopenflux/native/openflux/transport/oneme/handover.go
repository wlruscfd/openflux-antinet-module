package oneme

// Handover — сеть под транспортом сменилась (событие хоста, MODULE_API §2.8). Дословная копия
// openflux-server теперь несёт ForceReconnect сама (просит call-handler переустановить звонок его
// же петлёй, [CallHandler.signalReconnect] → reconnectCh) - модулю остаётся только назвать вещь его
// именем в терминах §2.8.
//
// Отдельным файлом, а не правкой вендорных `max_*.go`: те — дословные копии openflux-server, и
// апстрим-бамп сводится к перезаписи файлов.
func (t *OneMeTransport) Handover() {
	t.ForceReconnect()
}
