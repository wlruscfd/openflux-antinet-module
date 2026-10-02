// SPDX-License-Identifier: GPL-3.0-or-later
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/oneme"
	"universal-bypass-tool/transport/yandex"
)

func importLink(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return "openflux://import?data=" + base64.RawURLEncoding.EncodeToString(raw)
}

func TestImportLinkCarriesEveryServerTransport(t *testing.T) {
	for _, tr := range []string{"yandex", "volga", "mailru", "boards", "mts"} {
		t.Run(tr, func(t *testing.T) {
			l, err := parseOpenFluxLink(importLink(t, map[string]any{
				"name": "key-1", "mode": "key", "control_url": "https://203.0.113.5",
				"key_token": "tok-abc", "doc_url": "https://example.test/doc", "transport": tr,
				"e2e_encryption": true,
			}))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if l.Transport != tr || l.URL != "https://example.test/doc" {
				t.Fatalf("got %+v", l)
			}
			if !l.E2E || l.KeyToken != "tok-abc" {
				t.Fatalf("e2e/key lost on import: %+v", l)
			}
			if l.Name != "key-1" {
				t.Fatalf("name = %q", l.Name)
			}
		})
	}
}

func TestImportLinkDefaultsToYandexAndKeepsE2EOff(t *testing.T) {
	l, err := parseOpenFluxLink(importLink(t, map[string]any{"doc_url": "https://docs.yandex.ru/x", "key_token": "k"}))
	if err != nil {
		t.Fatal(err)
	}
	if l.Transport != transportYandex || l.E2E {
		t.Fatalf("got %+v", l)
	}
}

func TestImportLinkMultistream(t *testing.T) {
	l, err := parseOpenFluxLink(importLink(t, map[string]any{
		"transport": "yandex_multistream", "doc_urls": []string{"https://a.test/1", " ", "https://b.test/2"},
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(l.URLs) != 2 || l.server() != "a.test (+1)" {
		t.Fatalf("got %+v server=%q", l, l.server())
	}
	if _, err := parseOpenFluxLink(importLink(t, map[string]any{"transport": "yandex_multistream", "doc_urls": []string{"https://a.test/1"}})); err == nil {
		t.Fatal("a single doc_url must not pass for multistream")
	}
}

func TestImportLinkRejectsBrokenInput(t *testing.T) {
	for name, link := range map[string]string{
		"no doc_url":        importLink(t, map[string]any{"transport": "mts"}),
		"unknown transport": importLink(t, map[string]any{"transport": "carrier-pigeon", "doc_url": "x"}),
		"bad base64":        "openflux://import?data=***",
		"foreign scheme":    "https://example.test",
		"empty":             "",
	} {
		if _, err := parseOpenFluxLink(link); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestPlainLinkForms(t *testing.T) {
	l, err := parseOpenFluxLink("openflux://boards?url=https%3A%2F%2Fboards.yandex.ru%2Fx&key=tk&e2e=1#My%20board")
	if err != nil {
		t.Fatal(err)
	}
	if l.Transport != transportBoards || l.URL != "https://boards.yandex.ru/x" || !l.E2E || l.KeyToken != "tk" || l.Name != "My board" {
		t.Fatalf("got %+v", l)
	}

	m, err := parseOpenFluxLink("openflux://multistream?url=https%3A%2F%2Fa.test%2F1&url=https%3A%2F%2Fb.test%2F2")
	if err != nil || m.Transport != transportMulti || len(m.URLs) != 2 {
		t.Fatalf("multistream: %+v err=%v", m, err)
	}

	o, err := parseOpenFluxLink("openflux://oneme?token=t&uid=42")
	if err != nil || o.UID != 42 || o.server() != "max.ru:42" {
		t.Fatalf("oneme: %+v err=%v", o, err)
	}
}

func TestSummarizeAndNormalize(t *testing.T) {
	got := moduleCall("summarize", importLink(t, map[string]any{"name": "Home", "doc_url": "https://mts-link.example/board/1", "transport": "mts"}))
	if got != "Home\nmts-link.example" {
		t.Fatalf("summarize = %q", got)
	}
	if moduleCall("summarize", "garbage") != "\n" {
		t.Fatal("garbage must give two empty lines")
	}

	norm := moduleCall("normalize", `{"transport":"mailru","doc_url":"https://cloud.mail.ru/public/x","key_token":"k","e2e_encryption":true,"name":"N"}`)
	l, err := parseOpenFluxLink(norm)
	if err != nil {
		t.Fatalf("normalized link %q does not parse: %v", norm, err)
	}
	if l.Transport != transportMailru || l.KeyToken != "k" || !l.E2E || l.Name != "N" {
		t.Fatalf("normalize lost data: %+v", l)
	}
	if moduleCall("normalize", `{"transport":"mailru"}`) != "" {
		t.Fatal("a JSON without a doc url must not normalize")
	}
}

func TestBuildTransportShapes(t *testing.T) {
	cfg := transport.DefaultConfig()
	doc := "https://example.test/doc"

	cases := []struct {
		name        string
		link        openFluxLink
		wantCookies bool
		check       func(t *testing.T, b builtTransport)
	}{
		{"yandex plain", openFluxLink{Transport: transportYandex, URL: doc}, true, func(t *testing.T, b builtTransport) {
			if _, ok := b.trans.(*yandex.YandexDocsTransport); !ok {
				t.Fatalf("yandex must be used bare (self-compressing), got %T", b.trans)
			}
		}},
		{"yandex e2e", openFluxLink{Transport: transportYandex, URL: doc, KeyToken: "k", E2E: true}, true, nil},
		{"multistream", openFluxLink{Transport: transportMulti, URL: doc, URLs: []string{doc, doc + "2"}, KeyToken: "k", E2E: true}, true, func(t *testing.T, b builtTransport) {
			if _, ok := b.trans.(*transport.MultiStreamTransport); !ok {
				t.Fatalf("got %T", b.trans)
			}
		}},
		{"boards", openFluxLink{Transport: transportBoards, URL: doc}, true, func(t *testing.T, b builtTransport) {
			if _, ok := b.trans.(*transport.BatchedTransport); !ok {
				t.Fatalf("boards must be batched, got %T", b.trans)
			}
		}},
		{"boards e2e", openFluxLink{Transport: transportBoards, URL: doc, KeyToken: "k", E2E: true}, true, nil},
		{"volga", openFluxLink{Transport: transportVolga, URL: doc}, false, nil},
		{"mailru", openFluxLink{Transport: transportMailru, URL: doc}, false, nil},
		{"mts e2e", openFluxLink{Transport: transportMTS, URL: doc, KeyToken: "k", E2E: true}, false, nil},
		{"oneme", openFluxLink{Transport: transportOneMe, Token: "t", UID: 7}, false, func(t *testing.T, b builtTransport) {
			if _, ok := b.handover.(*oneme.OneMeTransport); !ok {
				t.Fatalf("oneme keeps its own Handover, got %T", b.handover)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := buildTransport(tc.link, cfg, captchaAuto)
			if err != nil {
				t.Fatal(err)
			}
			if b.trans == nil || b.handover == nil {
				t.Fatalf("incomplete: %+v", b)
			}
			if (b.cookies != nil) != tc.wantCookies {
				t.Fatalf("cookie provider presence = %v, want %v", b.cookies != nil, tc.wantCookies)
			}
			if tc.check != nil {
				tc.check(t, b)
			}
		})
	}

	if _, err := buildTransport(openFluxLink{Transport: "nope"}, cfg, captchaAuto); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown transport must error, got %v", err)
	}
}

func TestE2EOnlyWhenKeyPresent(t *testing.T) {
	cfg := transport.DefaultConfig()
	b, err := buildTransport(openFluxLink{Transport: transportMailru, URL: "https://x.test/d", E2E: true}, cfg, captchaAuto)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := buildTransport(openFluxLink{Transport: transportMailru, URL: "https://x.test/d"}, cfg, captchaAuto)
	if err != nil {
		t.Fatal(err)
	}
	if typeName(b.trans) != typeName(plain.trans) {
		t.Fatalf("e2e without a key token must degrade to the plain stack: %s vs %s", typeName(b.trans), typeName(plain.trans))
	}
}

func typeName(v any) string { return fmt.Sprintf("%T", v) }
