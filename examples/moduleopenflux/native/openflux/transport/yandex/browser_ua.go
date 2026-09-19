package yandex

import "net/http"

// browserUserAgent is a real, currently-plausible Firefox fingerprint; a convincing header set can't fix IP-reputation challenges, but an otherwise bare request (User-Agent only) was itself a detectable tell.
const browserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"

// applyBrowserGetHeaders deliberately skips Accept-Encoding (would disable Go's transparent decompression) and Chromium-only Sec-Ch-Ua hints (a Firefox UA sending them is a bigger tell than sending neither).
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
