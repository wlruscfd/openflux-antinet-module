package yandex

import "net/http"

// browserUserAgent is a real, currently-plausible desktop Firefox
// fingerprint, shared by every request this package makes to Yandex's own
// servers (fetchDocInfo/WebSocket dial here, volgaUserAgent in volga.go).
//
// Yandex's own bot detection has reportedly gotten more aggressive lately:
// a CAPTCHA page in place of the real client-config, especially from VPS
// IP ranges outside Russia. A convincing header set can't fix IP-
// reputation-based challenges (a datacenter IP can still get flagged no
// matter how real the headers look - that part genuinely isn't something
// request headers can work around), but fetchDocInfo's own request used to
// set User-Agent and nothing else - no real browser ever makes a request
// that bare, and that mismatch alone is exactly the kind of signal
// detection keys off before IP reputation even enters into it.
const browserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"

// applyBrowserGetHeaders sets the header set a real Firefox top-level page
// load carries, not just User-Agent. Deliberately doesn't set
// Accept-Encoding: a real Firefox sends "gzip, deflate, br", but setting it
// ourselves would disable Go's own transparent response decompression
// (net/http only auto-decompresses when it set that header itself) without
// us then decompressing the body by hand - trading a minor, low-value
// fingerprint detail for a real risk of silently parsing gzipped bytes as
// HTML. Also deliberately doesn't set Sec-Ch-Ua/Sec-Ch-Ua-Platform/
// Sec-Ch-Ua-Mobile - those are Chromium-only client hints; a Firefox UA
// sending them would be a more obvious tell than sending neither.
func applyBrowserGetHeaders(h http.Header) {
	h.Set("User-Agent", browserUserAgent)
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	h.Set("Accept-Language", "ru-RU,ru;q=0.8,en-US;q=0.5,en;q=0.3")
	h.Set("Upgrade-Insecure-Requests", "1")
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Site", "none")
	h.Set("Sec-Fetch-User", "?1")
}
