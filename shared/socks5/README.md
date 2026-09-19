# shared/socks5 — канонический SOCKS5-фронт модулей (инжектируется build.py)

**Единый источник всего протокола SOCKS5** для модулей AntiNet: рукопожатие, авторизация
(user/pass, RFC 1929), разбор запроса, accept-петля, реле CONNECT-соединения и UDP ASSOCIATE
(RFC 1928 §7). Модуль не пишет ничего из этого сам.

## Зачем канон именно здесь

Контракт модуля с хостом — SOCKS5-порт (`MODULE_API.md` §2.6), и он один и тот же у всех модулей.
Значит и протокол один. Разным у модулей остаётся ровно одно: **чем** они дозваниваются до цели.

⛔ **Свою копию протокола рядом писать не надо.** Она разойдётся с каноном — и не в сборке, а в
рантайме на чужой машине: собственная реализация SOCKS5 выглядит рабочей ровно до первого угла
(закрытый листенер, netstack-апстрим без `*net.TCPConn`, недостижимая семья адреса в
UDP-датаграмме). Нужен другой транспорт — реализуйте интерфейс ниже, протокол не трогайте.

## Как подключить

1. В `module.json`: `"socks5": true`.
2. `build.py` копирует `socks5shared.go` в main-пакет helper'а перед сборкой и удаляет после.
   **В дереве модуля этого файла нет и класть его туда не надо.**

## Что даёт канон

| Символ | Что делает |
|---|---|
| `socksHandshake(c, br, user, pass) (socksRequest, bool)` | приветствие → user/pass → разбор запроса. Отказы (чужая команда, неизвестный ATYP, неверные креды) отвечает сам; `false` = дальше говорить не о чем |
| `socksRequest` | `Cmd` / `Host` (непусто для домена) / `IP` (для литерала) / `Port`; `IsIP()`, `TargetLabel()` |
| `socksCmdConnect`, `socksCmdUDPAssociate` | коды команд |
| `serveSocksListener(ln, handle)` | accept-петля: транзиентную ошибку переживает, закрытый листенер завершает |
| `relayBidi(client, br, up, target, since)` | двунаправленное реле с честной политикой закрытия |
| `relayCopy(dst, src)` | копир с раздельными ошибками чтения и записи |
| `serveSocksUDPAssociate(ctrl, br, transport)` | всё UDP-реле: bind loopback, BND-ответ, дренаж control-conn'а, кэш per-target, обёртка ответов, счётчики |
| `socksRep(rep)`, `socksReadLP(br)` | ответ протокола, чтение length-prefixed поля |
| `parseSocksUDP`, `buildSocksUDPHeader` | wire-формат UDP-датаграммы |
| `errSocksTargetUnreachable` | «до этой семьи адресов отсюда пути нет» — вернуть из `DialUDPTarget` |

## Что обязан дать модуль — только транспорт

```go
type socksUDPTransport interface {
    LookupHost(host string) ([]string, error)      // что «резолв» значит именно для вашего модуля
    DialUDPTarget(dst netip.AddrPort) (net.Conn, error)
}
```

Плюс свой CONNECT-дозвон между `socksHandshake` и `relayBidi`. Скелет:

```go
func handleConn(c net.Conn, user, pass string) {
    defer c.Close()
    br := bufio.NewReader(c)

    req, ok := socksHandshake(c, br, user, pass)
    if !ok {
        return
    }
    if req.Cmd == socksCmdUDPAssociate {
        serveSocksUDPAssociate(c, br, myTransport{...})
        return
    }

    start := time.Now()
    up, err := myDial(req)              // ← единственное, что здесь ваше
    if err != nil {
        _, _ = c.Write(socksRep(0x01))
        return
    }
    defer up.Close()
    if _, err := c.Write(socksRep(0x00)); err != nil {
        return
    }
    relayBidi(c, br, up, req.TargetLabel(), start)
}
```

Слушающий сокет создаёт хост и передаёт его модулю (§2.6) — `serveSocksListener` принимает готовый
`net.Listener`, самому биндить не надо.

## Референсы

- `(репозиторий AntiNet) examples/moduleqwdtt/native/qwdtt/socks5.go` — `cachedResolver`: резолв и дозвон через свой
  WG-туннель (цель уже внутри установленного туннеля), плюс гейт по семье адреса, который туннель
  реально несёт.
- `(репозиторий AntiNet) examples/moduleecho/native/echo/cmd/helper/main.go` — `echoUDPTransport`: off-tunnel резолвер и
  protected-dialer (цель снаружи, сокет обязан идти мимо TUN).

## Чего в каноне нет и не будет

Резолва, дозвона и любой политики выбора адреса. Канон не знает, есть ли у модуля туннель, какие
семьи адресов он несёт и что для него значит «резолв» — он лишь зовёт переданный интерфейс.
Недостижимость семьи модуль сообщает ошибкой `errSocksTargetUnreachable`, и канон ведёт для неё
отдельный счётчик: «датаграмма битая», «адресат вне достижимых семей» и «дозвон не удался» — три
разных диагноза, и в одну строку их сливать нельзя.
