package transport

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

// DialContextFunc — чем транспорты дозваниваются наружу. Обычным сокетом им нельзя ни на одной
// платформе:
//
//   - Android: helper живёт под UID AntiNet, а наш UID ВКЛЮЧЁН в TUN (Husi-pattern). Незащищённый
//     сокет уходит в НАШ ЖЕ туннель → петля (модуль и есть выход из него). Лечится SCM_RIGHTS-
//     protect'ом каждого исходящего fd (MODULE_API §2.3 п.2);
//   - Desktop: «прямой» маршрут по умолчанию может принадлежать ЧУЖОМУ VPN-клиенту, а в
//     proxy-only-режиме нашего TUN нет вовсе. Лечится bind'ом к физическому адаптеру
//     (канон shared/offtun).
//
// Обе механики — КАНОНЫ, они живут в helper'е и инжектируются build.py; сюда приезжает только
// готовая функция. Передаётся ЯВНЫМ ПАРАМЕТРОМ конструктора, а не package-level `var`,
// заполняемым отдельным `init()` — MODULE_API §4 описывает ровно этот антипаттерн как пойманный
// живьём класс «объявили переменную-функцию, забыли её заполнить, `go build` чист, рантайм —
// nil-dereference на первом же обращении».
//
// Резолв имён внутри неё — тоже забота helper'а (protected off-tunnel резолвер): сюда она
// приходит уже умеющей и то и другое.
type DialContextFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// NewHTTPClient — http.Client, чьи соединения идут ЧЕРЕЗ dial (nil → системный дозвон).
func NewHTTPClient(dial DialContextFunc, timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if dial != nil {
		tr.DialContext = dial
		// Прокси из окружения не наследуем: у VPN-модуля «системный прокси» — чужой путь наружу,
		// мимо protect'а и мимо физ-адаптера.
		tr.Proxy = nil
	}
	return &http.Client{
		Transport:     tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil },
		Timeout:       timeout,
	}
}

// NewWSDialer — websocket.Dialer, чьи соединения идут ЧЕРЕЗ dial (nil → системный дозвон).
// `NetDialContext` покрывает и `wss://`: gorilla поднимает TLS поверх него сам, если не задан
// `NetDialTLSContext`.
func NewWSDialer(dial DialContextFunc, handshakeTimeout time.Duration) *websocket.Dialer {
	d := &websocket.Dialer{HandshakeTimeout: handshakeTimeout}
	if dial != nil {
		d.NetDialContext = dial
	}
	return d
}
