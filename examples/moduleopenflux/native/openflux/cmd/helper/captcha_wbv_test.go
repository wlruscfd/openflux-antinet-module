package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/yandex"
)

func TestCookieHeader(t *testing.T) {
	tests := []struct {
		name string
		jar  map[string]string
		want string
	}{
		{"empty", map[string]string{}, ""},
		{"nil", nil, ""},
		{"single", map[string]string{"Session_id": "abc"}, "Session_id=abc"},
		{
			"sorted regardless of input order",
			map[string]string{"spravka": "1", "Session_id": "abc", "yandexuid": "2"},
			"Session_id=abc; spravka=1; yandexuid=2",
		},
		{
			"value with equals and spaces survives verbatim",
			map[string]string{"a": "x=y; z"},
			"a=x=y; z",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := cookieHeader(tc.jar); got != tc.want {
				t.Fatalf("cookieHeader() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCookieHeaderStableAcrossCalls(t *testing.T) {
	jar := map[string]string{
		"spravka": "1", "Session_id": "abc", "yandexuid": "2", "z": "3", "m": "4",
	}
	first := cookieHeader(jar)
	for i := 0; i < 200; i++ {
		if got := cookieHeader(jar); got != first {
			t.Fatalf("порядок пар нестабилен: %q != %q", got, first)
		}
	}
}

func TestCaptchaSolveModeFor(t *testing.T) {
	// auto ОБЯЗАН быть Native. Пустое значение captchaSolveMode у только что созданного
	// транспорта — это CaptchaSolveModeOff, а Off означает «капчу не решать»: транспорт
	// возвращает errCaptchaBlocked и модуль не поднимается, хост перезапускает его
	 // каждые readyWaitBudget. Регрессия ловилась именно здесь.
	tests := []struct {
		mode captchaMode
		want yandex.CaptchaSolveMode
	}{
		{captchaAuto, yandex.CaptchaSolveModeNative},
		{captchaWebviewOnly, yandex.CaptchaSolveModeExternal},
		{captchaOff, yandex.CaptchaSolveModeOff},
	}
	for _, tc := range tests {
		if got := captchaSolveModeFor(tc.mode); got != tc.want {
			t.Fatalf("captchaSolveModeFor(%v) = %q, want %q", tc.mode, got, tc.want)
		}
	}
}

// Регрессия, из-за которой модуль не подключался вообще: режим auto не должен давать
// ни Off, ни "" — иначе проверка не решается и транспорт не поднимается.
func TestAutoNeverLeavesCaptchaUnsolved(t *testing.T) {
	mode := captchaSolveModeFor(captchaAuto)
	if mode == "" {
		t.Fatal("auto дал пустой режим — это CaptchaSolveModeOff, капча не будет решена")
	}
	if mode == yandex.CaptchaSolveModeOff {
		t.Fatal("auto дал Off: транспорт вернёт errCaptchaBlocked и модуль не поднимется")
	}
	if mode == yandex.CaptchaSolveModeExternal {
		t.Fatal("auto отдал проверку наружу, но окно хоста может и не уметь отдавать cookie")
	}
}

func TestParseCaptchaMode(t *testing.T) {
	tests := []struct {
		raw  string
		want captchaMode
	}{
		{"", captchaAuto},
		{"auto", captchaAuto},
		{"wv", captchaWebviewOnly},
		{"webview", captchaWebviewOnly},
		{" WV ", captchaWebviewOnly},
		{"off", captchaOff},
		{"none", captchaOff},
		{"garbage", captchaAuto},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			if got := parseCaptchaMode(tc.raw); got != tc.want {
				t.Fatalf("parseCaptchaMode(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

type fakeCaptchaTransport struct {
	transport.Transport
	cb         func(code, detail string)
	reconnects chan struct{}
}

func (f *fakeCaptchaTransport) SetEventCallback(fn func(code, detail string)) { f.cb = fn }
func (f *fakeCaptchaTransport) ForceReconnect()                               { f.reconnects <- struct{}{} }

type fakeCookieProvider struct{ got chan string }

func (f *fakeCookieProvider) ProvideCookies(c string) { f.got <- c }

func withFakeWindow(t *testing.T, result string, cancelled bool) chan string {
	t.Helper()
	opened := make(chan string, 4)
	prev := captchaWindow
	captchaWindow = func(profileDir, docURL string) (string, bool) {
		opened <- docURL
		return result, cancelled
	}
	t.Cleanup(func() { captchaWindow = prev })
	return opened
}

func expectOpen(t *testing.T, opened chan string, want bool) {
	t.Helper()
	select {
	case <-opened:
		if !want {
			t.Fatal("the captcha window opened but must not have")
		}
	case <-time.After(300 * time.Millisecond):
		if want {
			t.Fatal("the captcha window did not open")
		}
	}
}

func TestAutoOpensWindowOnlyAfterProofOfWorkFailed(t *testing.T) {
	opened := withFakeWindow(t, "a=1; b=2", false)
	tr := &fakeCaptchaTransport{reconnects: make(chan struct{}, 2)}
	prov := &fakeCookieProvider{got: make(chan string, 2)}
	attachCaptchaSolver(tr, prov, t.TempDir(), captchaAuto)

	tr.cb(transport.EventCaptchaRequired, "https://docs.yandex.ru/x")
	expectOpen(t, opened, false)

	tr.cb(transport.EventRetrying, "1|180|captcha_blocked|proof of work failed")
	expectOpen(t, opened, true)
	if got := <-prov.got; got != "a=1; b=2" {
		t.Fatalf("cookies handed to the transport = %q", got)
	}
	select {
	case <-tr.reconnects:
	case <-time.After(time.Second):
		t.Fatal("transport was not reconnected after the cookies arrived")
	}
}

func TestAutoIgnoresNonCaptchaFailures(t *testing.T) {
	opened := withFakeWindow(t, "a=1", false)
	tr := &fakeCaptchaTransport{reconnects: make(chan struct{}, 1)}
	attachCaptchaSolver(tr, &fakeCookieProvider{got: make(chan string, 1)}, t.TempDir(), captchaAuto)
	tr.cb(transport.EventCaptchaRequired, "https://docs.yandex.ru/x")
	tr.cb(transport.EventRetrying, "1|5|fetch_failed|timeout")
	expectOpen(t, opened, false)
}

func TestWebviewModeOpensWindowImmediately(t *testing.T) {
	opened := withFakeWindow(t, "a=1", false)
	tr := &fakeCaptchaTransport{reconnects: make(chan struct{}, 1)}
	attachCaptchaSolver(tr, &fakeCookieProvider{got: make(chan string, 1)}, t.TempDir(), captchaWebviewOnly)
	tr.cb(transport.EventCaptchaRequired, "https://docs.yandex.ru/x")
	expectOpen(t, opened, true)
}

func TestOffModeAndMissingProviderNeverOpenWindow(t *testing.T) {
	opened := withFakeWindow(t, "a=1", false)
	off := &fakeCaptchaTransport{reconnects: make(chan struct{}, 1)}
	attachCaptchaSolver(off, &fakeCookieProvider{got: make(chan string, 1)}, t.TempDir(), captchaOff)
	off.cb(transport.EventCaptchaRequired, "https://docs.yandex.ru/x")
	off.cb(transport.EventRetrying, "1|180|captcha_blocked|x")

	bare := &fakeCaptchaTransport{reconnects: make(chan struct{}, 1)}
	attachCaptchaSolver(bare, nil, t.TempDir(), captchaWebviewOnly)
	bare.cb(transport.EventCaptchaRequired, "https://docs.yandex.ru/x")
	expectOpen(t, opened, false)
}

func TestCancelledWindowIsNotReopenedOnEveryRetry(t *testing.T) {
	opened := withFakeWindow(t, "", true)
	tr := &fakeCaptchaTransport{reconnects: make(chan struct{}, 1)}
	attachCaptchaSolver(tr, &fakeCookieProvider{got: make(chan string, 1)}, t.TempDir(), captchaAuto)
	tr.cb(transport.EventCaptchaRequired, "https://docs.yandex.ru/x")
	tr.cb(transport.EventRetrying, "1|180|captcha_blocked|x")
	expectOpen(t, opened, true)
	time.Sleep(100 * time.Millisecond)
	tr.cb(transport.EventRetrying, "2|180|captcha_blocked|x")
	expectOpen(t, opened, false)
}

func TestReadyBudgetIsPausedWhileTheWindowIsOpen(t *testing.T) {
	captchaPending.Store(true)
	defer captchaPending.Store(false)
	done := make(chan bool, 1)
	go func() { done <- waitTransportUpFor(&neverUp{}, 400*time.Millisecond) }()
	select {
	case <-done:
		t.Fatal("waitTransportUp gave up while the captcha window was still open")
	case <-time.After(1200 * time.Millisecond):
	}
}

type neverUp struct{ transport.Transport }

func (neverUp) IsConnected() bool { return false }

func captureStdout(t *testing.T) (lines chan string, restore func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	lines = make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	return lines, func() {
		os.Stdout = old
		w.Close()
	}
}

func TestWebviewActionIsEmittedAndCookiesAreCollected(t *testing.T) {
	rememberHostFeatures("webview.cookies,webview.leavePattern,webview.doneButton")
	ofText = ofStringsEN
	lines, restore := captureStdout(t)
	defer restore()

	type result struct {
		jar       string
		cancelled bool
	}
	done := make(chan result, 1)
	go func() {
		jar, cancelled := solveCaptchaByWebView(t.TempDir(), "https://docs.yandex.ru/edit/d/x")
		done <- result{jar, cancelled}
	}()

	var id string
	var rule map[string]any
	deadline := time.After(3 * time.Second)
	for rule == nil {
		select {
		case line := <-lines:
			_, rest, ok := strings.Cut(line, "ACTION_REQUIRED|")
			if !ok {
				continue
			}
			var payload string
			id, payload, _ = strings.Cut(rest, "|")
			raw, err := base64.StdEncoding.DecodeString(payload)
			if err != nil {
				t.Fatalf("payload is not base64: %v", err)
			}
			if err := json.Unmarshal(raw, &rule); err != nil {
				t.Fatalf("payload is not JSON: %v", err)
			}
		case <-deadline:
			t.Fatal("no ACTION_REQUIRED marker was printed")
		}
	}

	if rule["type"] != "webview" || rule["url"] != "https://docs.yandex.ru/edit/d/x" || rule["collectCookies"] != true {
		t.Fatalf("rule = %v", rule)
	}
	if rule["doneButton"] != true || rule["userAgent"] == "" || rule["title"] != ofStringsEN.captchaWindowTitle {
		t.Fatalf("rule = %v", rule)
	}
	patterns, _ := rule["leavePattern"].([]any)
	if len(patterns) == 0 {
		t.Fatalf("leavePattern missing: %v", rule)
	}

	answer := `{"type":"webview","cookies":{"https://docs.yandex.ru/":"spravka=1; Session_id=abc","https://yandex.ru/":"yandexuid=7"}}`
	handleHostEvent("ACTION_RESULT|" + id + "|" + base64.StdEncoding.EncodeToString([]byte(answer)))

	select {
	case res := <-done:
		if res.cancelled || res.jar != "Session_id=abc; spravka=1; yandexuid=7" {
			t.Fatalf("jar = %q cancelled = %v", res.jar, res.cancelled)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("solveCaptchaByWebView did not return after ACTION_RESULT")
	}
}

func TestWebviewActionCancelledByHost(t *testing.T) {
	rememberHostFeatures("webview.cookies")
	lines, restore := captureStdout(t)
	defer restore()

	done := make(chan bool, 1)
	go func() {
		_, cancelled := solveCaptchaByWebView(t.TempDir(), "https://docs.yandex.ru/x")
		done <- cancelled
	}()
	var id string
	for id == "" {
		select {
		case line := <-lines:
			if _, rest, ok := strings.Cut(line, "ACTION_REQUIRED|"); ok {
				id, _, _ = strings.Cut(rest, "|")
			}
		case <-time.After(3 * time.Second):
			t.Fatal("no ACTION_REQUIRED marker")
		}
	}
	handleHostEvent("ACTION_RESULT|" + id + "|CANCELLED")
	select {
	case cancelled := <-done:
		if !cancelled {
			t.Fatal("CANCELLED from the host must be reported as cancelled")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no return after CANCELLED")
	}
}

func TestWebviewActionSkippedWhenHostCannotReturnCookies(t *testing.T) {
	rememberHostFeatures("")
	lines, restore := captureStdout(t)
	jar, cancelled := solveCaptchaByWebView(t.TempDir(), "https://docs.yandex.ru/x")
	restore()
	if jar != "" || cancelled {
		t.Fatalf("got jar=%q cancelled=%v", jar, cancelled)
	}
	for line := range lines {
		if strings.Contains(line, "ACTION_REQUIRED") {
			t.Fatal("a window that cannot return cookies must not be requested")
		}
	}
}
