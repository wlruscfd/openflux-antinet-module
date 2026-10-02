package transport

import "testing"

type fakeStream struct {
	sent      [][]byte
	connected bool
	stats     TransportStats
	recvCB    func([]byte)
}

func (f *fakeStream) Start() error { return nil }
func (f *fakeStream) Stop() error  { return nil }
func (f *fakeStream) Send(data []byte) error {
	f.sent = append(f.sent, data)
	return nil
}
func (f *fakeStream) Receive(cb func([]byte))               { f.recvCB = cb }
func (f *fakeStream) IsConnected() bool                     { return f.connected }
func (f *fakeStream) Stats() TransportStats                 { return f.stats }
func (f *fakeStream) SetEventCallback(func(string, string)) {}
func (f *fakeStream) ForceReconnect()                       {}

func packet(srcPort, dstPort uint16) []byte {
	p := make([]byte, 24)
	p[0] = 0x45 // version 4, header length 5*4=20
	p[20] = byte(srcPort >> 8)
	p[21] = byte(srcPort)
	p[22] = byte(dstPort >> 8)
	p[23] = byte(dstPort)
	return p
}

func TestStreamIndexConsistentAcrossFlowDirection(t *testing.T) {
	request := packet(51000, 443)
	reply := packet(443, 51000)

	if streamIndex(request, 4) != streamIndex(reply, 4) {
		t.Errorf("request and reply of the same flow picked different streams")
	}
}

func TestStreamIndexSpreadsDifferentFlows(t *testing.T) {
	seen := make(map[int]bool)
	for port := uint16(1); port <= 40; port++ {
		seen[streamIndex(packet(port, 443), 4)] = true
	}
	if len(seen) < 2 {
		t.Errorf("40 different flows all landed on the same stream out of 4")
	}
}

func TestStreamIndexSingleStreamAlwaysZero(t *testing.T) {
	if idx := streamIndex(packet(1234, 443), 1); idx != 0 {
		t.Errorf("streamIndex with n=1 = %d, want 0", idx)
	}
}

func TestStreamIndexShortPacketDoesNotPanic(t *testing.T) {
	if idx := streamIndex([]byte{1, 2, 3}, 4); idx != 0 {
		t.Errorf("streamIndex on a too-short packet = %d, want 0", idx)
	}
}

func TestMultiStreamSendIsFlowSticky(t *testing.T) {
	streams := []Transport{&fakeStream{}, &fakeStream{}, &fakeStream{}}
	m := NewMultiStreamTransport(streams)

	for i := 0; i < 10; i++ {
		if err := m.Send(packet(51000, 443)); err != nil {
			t.Fatalf("Send #%d: %v", i, err)
		}
	}

	got := 0
	for _, s := range streams {
		if n := len(s.(*fakeStream).sent); n > 0 {
			got++
			if n != 10 {
				t.Errorf("stream got %d packets, want all 10 of the same flow", n)
			}
		}
	}
	if got != 1 {
		t.Errorf("one flow landed on %d streams, want exactly 1", got)
	}
}

func TestMultiStreamReceiveMergesAllStreams(t *testing.T) {
	streams := []Transport{&fakeStream{}, &fakeStream{}}
	m := NewMultiStreamTransport(streams)

	var got [][]byte
	m.Receive(func(d []byte) { got = append(got, d) })

	streams[0].(*fakeStream).recvCB([]byte("from stream 0"))
	streams[1].(*fakeStream).recvCB([]byte("from stream 1"))

	if len(got) != 2 {
		t.Fatalf("got %d callbacks, want 2", len(got))
	}
}

func TestMultiStreamIsConnectedIfAnyStreamUp(t *testing.T) {
	m := NewMultiStreamTransport([]Transport{&fakeStream{connected: false}, &fakeStream{connected: true}})
	if !m.IsConnected() {
		t.Errorf("IsConnected() = false, want true with one stream up")
	}

	m2 := NewMultiStreamTransport([]Transport{&fakeStream{connected: false}, &fakeStream{connected: false}})
	if m2.IsConnected() {
		t.Errorf("IsConnected() = true, want false with no streams up")
	}
}

func TestMultiStreamStatsSumsAcrossStreams(t *testing.T) {
	m := NewMultiStreamTransport([]Transport{
		&fakeStream{stats: TransportStats{BytesSent: 100, PacketsSent: 1}},
		&fakeStream{stats: TransportStats{BytesSent: 200, PacketsSent: 2}},
	})

	stats := m.Stats()
	if stats.BytesSent != 300 {
		t.Errorf("BytesSent = %d, want 300", stats.BytesSent)
	}
	if stats.PacketsSent != 3 {
		t.Errorf("PacketsSent = %d, want 3", stats.PacketsSent)
	}
}
