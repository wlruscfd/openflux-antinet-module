# `shared/dns` — канон protected off-tunnel резолвера

Один файл: `dns_resolver.go` (`package main`, без build-тега). `build.py` копирует его в main-пакет
helper'а ПЕРЕД сборкой и удаляет ПОСЛЕ — в дереве модуля его нет и быть не должно.

**Гейт: `"dnsResolver": true` в `module.json`.** Флаг build-time-only — его читает только таблица
`CANONS` в `build.py`, ни один хост его не разбирает и в плоский `dist/*/module.json` он не едет.

## Зачем

Модуль резолвит СВОИ dial-цели: хост CONNECT-запроса, домен UDP-таргета (RFC 1928 §7), адреса
собственного апстрима. Обычный `net.DefaultResolver` тут не годится: `Control`-хук висит на сокете
ДОЗВОНА, а `LookupHost` открывает свои сокеты внутри себя — они остаются незащищёнными и на Android
уходят в TUN (наш UID внутри туннеля, Husi-pattern). Дальше их ловит DNS-hijack-правило sing-box'а,
и резолв модуля едет через ЧУЖОЙ пайплайн (`dns-remote`/direct/local): не сломано, но
непредсказуемо медленно и зависит от состояния активного каскада.

Канон дозванивается до реального физического DNS напрямую UDP-ом, ЧЕРЕЗ `dialControl` самого
модуля — то есть тем же примитивом, что защищает его CONNECT-сокет.

**Кому НЕ нужен:** модулю, который резолвит ВНУТРИ уже поднятого туннеля (qWDTT — через свой
netstack). Там изоляция от TUN дана самим туннелем, и флаг объявлять незачем.

## Что даёт

```go
r := newProtectedResolver(cfg["DNS_SERVERS"], protectPath)
ips, err := r.LookupHost("example.org")
```

- `DNS_SERVERS=<ip[,ip...]>` — generic ключ конфига (MODULE_API §2.3): РЕАЛЬНЫЕ физические DNS сети,
  которые хост берёт тем же примитивом, что и для остального клиента. Пусто (старый хост /
  детект не удался) → фоллбэк на `net.DefaultResolver.LookupHost`;
- TTL-кэш 60с + single-flight: без кэша каждое соединение к тому же хосту платит полный резолв
  заново, без single-flight параллельные дозвоны дублируют запрос (thundering herd);
- A, затем AAAA; по серверам — по очереди, первый успех побеждает;
- сигнатура `LookupHost(string) ([]string, error)` совпадает с интерфейсом `socksResolver` канона
  `shared/socks5` — резолвер отдаётся в `serveSocksUDPAssociate` как есть.

## Что канон требует от модуля

Только `golang.org/x/net` в `go.mod` (пакет `dns/dnsmessage`). Сам `dialControl` писать не надо — он
тоже канон и приезжает безусловно (android-половина в `shared/protect`, десктопная в `shared/offtun`).

## Референс

`examples/moduleecho` — `newProtectedResolver(cfg["DNS_SERVERS"], protectPath)` в `realMain`,
дальше `resolver.LookupHost` на CONNECT-пути и он же внутри `echoUDPTransport`.
