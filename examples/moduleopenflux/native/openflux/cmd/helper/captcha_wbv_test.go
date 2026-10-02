package main

import (
	"testing"

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
