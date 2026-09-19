package oneme

// Handover reconnects on a host network-change event (MODULE_API §2.8) via ForceReconnect.
func (t *OneMeTransport) Handover() {
	t.ForceReconnect()
}
