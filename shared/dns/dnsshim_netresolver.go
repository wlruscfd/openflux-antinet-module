// SPDX-License-Identifier: MIT

package main

// КАНОН shared/dns — ПРОКЛАДКА К РЕЗОЛВЕРУ ПОД PROTECT'ОМ.
//
// Отдаёт СТАНДАРТНЫЙ `*net.Resolver`, а не свой интерфейс: его принимают `net.Dialer.Resolver`,
// `http.Transport` (через свой `DialContext`), да и сам `net.DefaultResolver` — модулю не нужно
// переучивать ни одну библиотеку, которой он уже пользуется. Всё, что прокладка меняет, — это
// КУДА уходит DNS-сокет и то, что он проходит через protect.
//
// ⛔ ПОЧЕМУ НЕЛЬЗЯ ПРОСТО `net.DefaultResolver`. На Android Go по умолчанию берёт cgo-резолвер
// (`goosPrefersCgo`, golang/go#10714), а тот НИКОГДА не идёт через `net.Dialer` — его сокет не
// проходит ни через один хук, значит его нечем защитить. Под VPN такой запрос уходит в TUN, то
// есть в туннель, который держится на самом модуле: модуль ждёт резолва, чтобы поднять транспорт,
// а резолв ждёт транспорта. Замыкание, и оно не лечится ретраем.
//
// ⛔ ПОЧЕМУ `PreferGo: true` ОБЯЗАТЕЛЕН. Ровно чтобы хук `Dial` ниже вообще вызвался: без него Go
// уходит в cgo-путь и до `Dial` дело не доходит. Цена — Go начинает читать `/etc/resolv.conf`,
// которого на Android нет; его `dnsReadConfig` падает на захардкоженный `defaultNS`
// (`127.0.0.1:53` и `[::1]:53`, см. src/net/dnsconfig_unix.go). Там никто не слушает, поэтому
// адрес, который Go просит у `Dial`, использовать нельзя — и `Dial` его игнорирует.
//
// СПИСОК — ФУНКЦИЕЙ, НЕ СРЕЗОМ. Единственный потребитель, которому хватило бы среза, — статический;
// а живой список (хост шлёт новый на каждой смене сети, событие `dns=`) — это та самая причина, по
// которой прокладка и понадобилась: резолвер, замкнувший на себя срез, после смены сети продолжит
// бить в резолверы прежней сети. Провайдер читается НА КАЖДЫЙ резолв, поэтому свежий список
// применяется без пересоздания резолвера. Статический случай оборачивается одной строкой:
// `func() []string { return list }`.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// dnsQueryTimeout — потолок ОДНОГО дозвона до резолвера. Живёт в прокладке, а не в кэширующем
// резолвере: прокладка инжектируется всегда, а резолвер — по флагу, и бюджет нужен обоим.
// Неограниченного ожидания здесь быть не должно: недостижимый резолвер обязан отваливаться
// быстро, иначе смена сети оборачивается паузой длиной в этот таймаут на КАЖДОМ сервере списка.
const dnsQueryTimeout = 3 * time.Second

// normalizeDNSServers — ЕДИНСТВЕННЫЙ разбор списка резолверов (bare IP → ip:53, мусор и пустые
// отбрасываются). Зовут её ВСЕ, у кого на руках оказывается список: прокладка ниже, обе
// платформенные половины `systemDNSServers` и кэширующий резолвер `dns_resolver.go`. Два разбора
// одного формата разошлись бы на первой же правке, а расхождение здесь означает, что после смены
// сети модуль резолвит не тем, чем при старте.
//
// Живёт в ПРОКЛАДКЕ, а не в резолвере: прокладка инжектируется всегда, резолвер — по флагу
// `dnsResolver`, и разбор списка нужен раньше, чем кому-то понадобится кэш.
// normalizeDNSCsv — тот же разбор, но для СЫРОЙ строки хоста (`DNS_SERVERS`, `dns=<...>`). Второй
// вход в один разбор, а не вторая грамматика: `strings.Split(csv, ",")` стоял отдельной строкой у
// каждого потребителя, и это ровно та форма, из которой вырастает расхождение — один потребитель
// начинает приводить голый IP к `ip:53`, другой нет.
func normalizeDNSCsv(csv string) []string {
	return normalizeDNSServers(strings.Split(csv, ","))
}

func normalizeDNSServers(servers []string) []string {
	out := make([]string, 0, len(servers))
	for _, s := range servers {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if net.ParseIP(s) != nil {
			s = net.JoinHostPort(s, "53")
		}
		out = append(out, s)
	}
	return out
}

// errNoDNSServers — резолвить нечем: провайдер отдал пустой список. ОТДЕЛЬНАЯ ошибка, а не
// «просто не получилось»: вызывающий обязан отличать «серверы есть, но не ответили» (сеть) от
// «серверов нет вовсе» (хост не определил физическую сеть, либо ОС не отдала свои). Второе на
// Android означает, что резолвить честным способом сейчас нечем, и уходить в обход — в TUN —
// нельзя.
var errNoDNSServers = errors.New("dns: no resolvers available")

// protectedNetResolver — `*net.Resolver`, который резолвит через серверы от `serversFn`,
// дозваниваясь до них под protect'ом (`dialControl` — тот же примитив, что защищает CONNECT-сокет
// модуля; его платформенная половина живёт в shared/protect на android и в shared/offtun на
// десктопе, имя одно).
//
// Протокол DNS целиком ведёт сам Go — прокладка отвечает ТОЛЬКО за сокет. Поэтому даром достаются
// вещи, которых у ручного пути (`queryOneServer`) нет: повтор по TCP на усечённом ответе, разбор
// CNAME-цепочек, search-домены, корректный таймаут на каждую попытку.
func protectedNetResolver(serversFn func() []string, protectPath string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var servers []string
			if serversFn != nil {
				servers = normalizeDNSServers(serversFn())
			}
			if len(servers) == 0 {
				return nil, errNoDNSServers
			}

			// Сначала тем транспортом, который просит Go (он сам переходит на TCP, когда ответ
			// пришёл усечённым), затем — вторым. Второй заход нужен там, где UDP до резолвера не
			// доходит вовсе: Go об этом не узнает и TCP сам не попробует, а провайдер, режущий
			// UDP/53, — обычное дело.
			var lastErr error
			for _, nw := range [...]string{network, otherDNSTransport(network)} {
				if nw == "" {
					continue
				}
				for _, srv := range servers {
					var pst protectStat
					d := net.Dialer{
						Timeout: dnsQueryTimeout,
						Control: dialControl(protectPath, &pst),
					}
					conn, err := d.DialContext(ctx, nw, srv)
					if err == nil {
						return conn, nil
					}
					lastErr = fmt.Errorf("dns: dial %s/%s: %w", nw, srv, err)
				}
			}
			return nil, lastErr
		},
	}
}

// otherDNSTransport — парный транспорт для второго захода. Go зовёт `Dial` с "udp"/"tcp" (иногда с
// суффиксом семьи — "udp4"/"tcp6"), поэтому развилка идёт по префиксу, а суффикс сохраняется: он
// несёт выбор семьи адреса, и терять его нельзя.
func otherDNSTransport(network string) string {
	switch {
	case len(network) >= 3 && network[:3] == "udp":
		return "tcp" + network[3:]
	case len(network) >= 3 && network[:3] == "tcp":
		return "udp" + network[3:]
	default:
		return ""
	}
}

// systemResolver — прокладка к резолверам САМОЙ ОС (`systemDNSServers`), под protect'ом.
//
// Это то, чем модуль пользуется как фоллбэком, когда свои резолверы не работают, а провайдерские
// неизвестны. Именно прокладка, а не `net.DefaultResolver`: список берётся у ОС, но запрос идёт
// нашим сокетом — мимо туннеля.
//
// Пусто → `errNoDNSServers` на каждом резолве. Так и задумано: см. `systemDNSServers` про Android,
// где своих резолверов у процесса нет вовсе.
func systemResolver(protectPath string) *net.Resolver {
	return protectedNetResolver(systemDNSServers, protectPath)
}
