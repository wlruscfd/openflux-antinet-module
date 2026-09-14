package transport

import (
	"sync"
	"sync/atomic"
	"time"
)

type TransportConfig struct {
	MaxReconnectAttempts int
	ReconnectDelay       time.Duration
	ReconnectMultiplier  float64
	MaxReconnectDelay    time.Duration
	MaxQueueSize         int
	KeepAliveInterval    time.Duration
}

type Transport interface {
	Start() error
	Stop() error
	Send(data []byte) error
	Receive(callback func([]byte))
	IsConnected() bool
	Stats() TransportStats
	SetEventCallback(fn func(code, detail string))
}

// Event codes reported via SetEventCallback/EmitEvent, for a human-facing
// connection log distinct from the coarser started/connected/stopped
// lifecycle a caller already gets some other way (e.g. mobile.Callback's
// OnStatus). detail's shape depends on code and is documented at each
// emitter - see yandex.YandexDocsTransport for the concrete transport that
// currently reports these.
const (
	// EventConnecting fires once per connection attempt, before it starts.
	// detail is the 1-based attempt number.
	EventConnecting = "connecting"
	// EventConnected fires once a connection attempt succeeds. detail is
	// the 1-based attempt number that succeeded.
	EventConnected = "connected"
	// EventRetrying fires when an attempt fails and another is scheduled
	// after a backoff delay. detail is
	// "<failed attempt>|<delay seconds>|<reason code>|<cause>", where cause
	// is the actual error's text (single line, newlines stripped) - reason
	// code alone only says which of a handful of fixed categories the
	// failure falls into, not what specifically went wrong.
	EventRetrying = "retrying"
)

type TransportStats struct {
	BytesSent     uint64
	BytesReceived uint64
	PacketsSent   uint64
	PacketsRecv   uint64
	Reconnects    uint64
	Connected     bool
	Uptime        time.Duration
}

func DefaultConfig() TransportConfig {
	return TransportConfig{
		MaxReconnectAttempts: 999999,
		// A previous version of this config carried ReconnectDelay: 0, which
		// made the (already-unused-until-now) exponential backoff a permanent
		// no-op: 0 * anything is still 0. Transports now actually apply
		// this - see yandex.(*YandexDocsTransport).backoffDelay - so a
		// failing connection retries with real, growing delays instead of
		// hammering the server in a tight loop.
		ReconnectDelay:      500 * time.Millisecond,
		ReconnectMultiplier: 1.6,
		MaxReconnectDelay:   30 * time.Second,
		MaxQueueSize:        1024,
		KeepAliveInterval:   10 * time.Second,
	}
}

type BaseTransport struct {
	config    TransportConfig
	running   atomic.Int32
	connected atomic.Int32
	stats     TransportStats
	startTime time.Time

	receiveCallback func([]byte)
	eventCallback   func(code, detail string)
	Mu              sync.RWMutex

	reconnectAttempts atomic.Int32
}

func NewBaseTransport(config TransportConfig) *BaseTransport {
	return &BaseTransport{
		config:    config,
		startTime: time.Now(),
	}
}

func (b *BaseTransport) Start() error {
	b.running.Store(1)
	b.startTime = time.Now()
	return nil
}

func (b *BaseTransport) Stop() error {
	b.running.Store(0)
	b.connected.Store(0)
	return nil
}

func (b *BaseTransport) IsRunning() bool {
	return b.running.Load() == 1
}

func (b *BaseTransport) IsConnected() bool {
	return b.connected.Load() == 1
}

func (b *BaseTransport) SetConnected(connected bool) {
	if connected {
		b.connected.Store(1)
	} else {
		b.connected.Store(0)
	}
}

func (b *BaseTransport) Receive(callback func([]byte)) {
	b.Mu.Lock()
	defer b.Mu.Unlock()
	b.receiveCallback = callback
}

func (b *BaseTransport) CallReceive(data []byte) {
	b.Mu.RLock()
	cb := b.receiveCallback
	b.Mu.RUnlock()
	if cb != nil {
		cb(data)
	}
}

// SetEventCallback registers fn to receive connection-lifecycle events (see
// the Event* constants) via EmitEvent. Not safe to change once a transport
// has started emitting - callers set it once, right after construction.
func (b *BaseTransport) SetEventCallback(fn func(code, detail string)) {
	b.Mu.Lock()
	defer b.Mu.Unlock()
	b.eventCallback = fn
}

// EmitEvent reports one event to whatever SetEventCallback registered, if
// anything. Concrete transports call this; it's a no-op with none set.
func (b *BaseTransport) EmitEvent(code, detail string) {
	b.Mu.RLock()
	fn := b.eventCallback
	b.Mu.RUnlock()
	if fn != nil {
		fn(code, detail)
	}
}

func (b *BaseTransport) GetSession(accessor func(interface{})) {
	b.Mu.RLock()
	defer b.Mu.RUnlock()
	// This is a helper for subclasses
}

func (b *BaseTransport) Stats() TransportStats {
	return TransportStats{
		BytesSent:     atomic.LoadUint64(&b.stats.BytesSent),
		BytesReceived: atomic.LoadUint64(&b.stats.BytesReceived),
		PacketsSent:   atomic.LoadUint64(&b.stats.PacketsSent),
		PacketsRecv:   atomic.LoadUint64(&b.stats.PacketsRecv),
		Reconnects:    uint64(b.reconnectAttempts.Load()),
		Connected:     b.IsConnected(),
		Uptime:        time.Since(b.startTime),
	}
}

func (b *BaseTransport) RecordSend(bytes int) {
	atomic.AddUint64(&b.stats.BytesSent, uint64(bytes))
	atomic.AddUint64(&b.stats.PacketsSent, 1)
}

func (b *BaseTransport) RecordReceive(bytes int) {
	atomic.AddUint64(&b.stats.BytesReceived, uint64(bytes))
	atomic.AddUint64(&b.stats.PacketsRecv, 1)
}

func (b *BaseTransport) RecordReconnect() {
	b.reconnectAttempts.Add(1)
}

func (b *BaseTransport) GetConfig() TransportConfig {
	return b.config
}
