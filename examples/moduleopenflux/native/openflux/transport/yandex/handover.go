package yandex

// Handover reconnects on a host network-change event (MODULE_API §2.8) instead of waiting out the full backoff.
func (t *YandexDocsTransport) Handover() {
	t.ForceReconnect()
}
