module github.com/p1neappleXpress/OpenFlux

go 1.26.6

require github.com/gorilla/websocket v1.5.3

require gvisor.dev/gvisor v0.0.0-20260530041128-23ef90c42be7

require (
	github.com/google/btree v1.1.2 // indirect
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/sys v0.48.0
	golang.org/x/time v0.15.0 // indirect
)

require (
	github.com/google/uuid v1.6.0
	github.com/klauspost/compress v1.20.0
	github.com/pierrec/lz4/v4 v4.1.27
	github.com/pion/interceptor v0.1.49
	github.com/pion/rtcp v1.2.18
	github.com/pion/rtp v1.10.5
	github.com/pion/sdp/v3 v3.0.20
	github.com/pion/transport/v5 v5.1.1
	github.com/pion/webrtc/v4 v4.2.22
	github.com/xjasonlyu/windivert-go v0.0.0-20201010013527-4239d0afa76f
	golang.org/x/crypto v0.57.0
	golang.org/x/net v0.59.0
)

require (
	github.com/pion/datachannel v1.6.3 // indirect
	github.com/pion/dtls/v3 v3.1.9 // indirect
	github.com/pion/ice/v4 v4.4.4 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.2.1 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/sctp v1.11.3 // indirect
	github.com/pion/srtp/v3 v3.1.0 // indirect
	github.com/pion/stun/v4 v4.0.1 // indirect
	github.com/pion/turn/v5 v5.1.2 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/mobile v0.0.0-20260908204917-8b95e45f8d3e // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
)

tool (
	golang.org/x/mobile/cmd/gobind
	golang.org/x/mobile/cmd/gomobile
)
