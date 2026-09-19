// SPDX-License-Identifier: MIT

package main

// Тесты канона shared/dns. Живут РЯДОМ С КАНОНОМ и приезжают в модуль тем же инжектом (маска
// `dns_*.go`), поэтому правится и проверяется по-прежнему одно место. Прогон — `build.py --test`.

import (
	"context"
	"errors"
	"net"
	"testing"
)

// TestProtectedNetResolverRefusesWithoutServers — резолвить нечем → ОТКАЗ.
//
// Это главный инвариант прокладки. Пустой список означает, что ни хост, ни ОС не дали ни одного
// резолвера; единственный оставшийся путь — системный резолвер Go, а он на Android идёт cgo-путём
// мимо `net.Dialer`, то есть мимо protect'а: под VPN запрос уходит в TUN, в туннель, который
// держится на этом же модуле. Отказ обязан быть громким и типизированным, чтобы вызывающий мог
// отличить его от «серверы есть, но молчат».
func TestProtectedNetResolverRefusesWithoutServers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		serversFn func() []string
	}{
		{"nil provider", nil},
		{"empty list", func() []string { return nil }},
		{"whitespace only", func() []string { return []string{"", "   "} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := protectedNetResolver(tc.serversFn, "")
			_, err := r.Dial(context.Background(), "udp", "127.0.0.1:53")
			if !errors.Is(err, errNoDNSServers) {
				t.Fatalf("ожидалась errNoDNSServers, получено: %v", err)
			}
		})
	}
}

// TestOtherDNSTransport — парный транспорт для второго захода. Суффикс семьи обязан выживать:
// он несёт выбор IPv4/IPv6, и потеря его увела бы повтор не в ту семью.
func TestOtherDNSTransport(t *testing.T) {
	for in, want := range map[string]string{
		"udp":  "tcp",
		"tcp":  "udp",
		"udp4": "tcp4",
		"tcp6": "udp6",
		"":     "",
		"ip":   "",
	} {
		if got := otherDNSTransport(in); got != want {
			t.Errorf("otherDNSTransport(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// TestHostDNSServersRoundTrip — список, присланный хостом, доходит до потребителя разобранным.
//
// Это и есть проверка ANDROID-половины `systemDNSServers`: там она возвращает ровно
// `hostDNSServers()`, потому что иначе резолверы системы внутри процесса взять неоткуда
// (`/etc/resolv.conf` не существует). Тест кроссплатформенный намеренно — проверяется хранилище,
// а не то, какая половина его читает.
func TestHostDNSServersRoundTrip(t *testing.T) {
	rememberHostDNSServers(" 192.0.2.1 , 192.0.2.2:5353 ")
	got := hostDNSServers()
	if len(got) != 2 {
		t.Fatalf("ожидалось 2 сервера, получено %v", got)
	}
	// Голый IP обязан получить порт, готовый ip:port — остаться как есть: разбор тот же, что у
	// конфига при старте, иначе после смены сети модуль резолвил бы не тем, чем при старте.
	if got[0] != "192.0.2.1:53" || got[1] != "192.0.2.2:5353" {
		t.Fatalf("разбор разошёлся с канонным: %v", got)
	}

	// Пустое от хоста означает «не смог определить физическую сеть». Затирать этим рабочий список
	// нельзя: это последнее, что осталось, ровно когда связи и так нет.
	rememberHostDNSServers("")
	rememberHostDNSServers("  ,  ")
	if after := hostDNSServers(); len(after) != 2 {
		t.Fatalf("пустое от хоста затёрло рабочий список: %v", after)
	}
}

// TestHostDNSReachesShimFromConfig — БОЕВОЙ путь, а не хранилище напрямую.
//
// Список от хоста забирает сам канон (`parseConfig` в shared/hostproto), чтобы модулю не
// доставалась обязанность, за невыполнение которой платят не сборкой, а молчаливой потерей
// фоллбэка на Android. Тест идёт от того, что реально приходит в процесс — текста конфига, — и
// ловит именно обрыв этой связи: без вызова в `parseConfig` он падает, сколько бы ни работало
// само хранилище.
func TestHostDNSReachesShimFromConfig(t *testing.T) {
	resetHostDNSForTest()
	parseConfig("LISTEN_PORT=1080\nDNS_SERVERS=198.51.100.7,198.51.100.8\nLINK=x\n")
	got := hostDNSServers()
	if len(got) != 2 || got[0] != "198.51.100.7:53" {
		t.Fatalf("конфиг хоста не доехал до прокладки: %v", got)
	}
}

// TestHostDNSReachesShimFromEvent — то же для события смены сети: `dns=` забирается в
// `handleHostEvent` ДО передачи модулю, потому что прокладке список нужен независимо от того,
// подписан ли модуль на это событие своим обработчиком.
func TestHostDNSReachesShimFromEvent(t *testing.T) {
	resetHostDNSForTest()
	handleHostEvent("dns=203.0.113.9")
	got := hostDNSServers()
	if len(got) != 1 || got[0] != "203.0.113.9:53" {
		t.Fatalf("событие dns= не доехало до прокладки: %v", got)
	}
}

// resetHostDNSForTest — хранилище и подписчики глобальны на процесс, а тесты идут в одном: без
// сброса каждый следующий видел бы состояние предыдущего и проходил бы по чужим данным. Подписки
// чистятся вместе со списком — иначе резолверы, созданные прошлыми тестами, продолжали бы
// получать обновления и держаться в памяти.
func resetHostDNSForTest() {
	hostDNSMu.Lock()
	hostDNSList = nil
	hostDNSWatchers = nil
	hostDNSMu.Unlock()
}

// TestSystemDNSServersNormalized — что бы ни отдала ОС, наружу идут адреса с портом: их напрямую
// принимает `net.Dialer.DialContext`. Сам список зависит от машины, поэтому проверяется ФОРМА, а
// не содержимое — пустой ответ здесь легитимен (Android, контейнер без resolv.conf).
func TestSystemDNSServersNormalized(t *testing.T) {
	for _, s := range systemDNSServers() {
		if _, _, err := net.SplitHostPort(s); err != nil {
			t.Errorf("systemDNSServers отдал %q без порта: %v", s, err)
		}
	}
}
