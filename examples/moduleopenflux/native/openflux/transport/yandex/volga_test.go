package yandex

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestDecodeBatchMultipleFrames(t *testing.T) {
	var buf bytes.Buffer
	for _, p := range [][]byte{[]byte("hello"), []byte("world")} {
		buf.WriteByte(0)
		buf.WriteByte(byte(len(p)))
		buf.Write(p)
	}

	got := decodeBatch(buf.Bytes())
	if len(got) != 2 || string(got[0]) != "hello" || string(got[1]) != "world" {
		t.Fatalf("decodeBatch = %q, want [hello world]", got)
	}
}

func TestDecodeBatchTruncatedFrameStopsCleanly(t *testing.T) {
	data := []byte{0, 10, 'a', 'b'}
	got := decodeBatch(data)
	if len(got) != 1 || string(got[0]) != "ab" {
		t.Fatalf("decodeBatch(truncated) = %q, want [ab] (raw fallback of the leftover tail)", got)
	}
}

func TestDecodeBatchZeroLengthFrameStopsCleanly(t *testing.T) {
	data := []byte{0, 0}
	if got := decodeBatch(data); len(got) != 0 {
		t.Errorf("decodeBatch(zero-length frame, nothing after) = %q, want none", got)
	}
}

func TestDecodeBatchEmptyInput(t *testing.T) {
	if got := decodeBatch(nil); len(got) != 0 {
		t.Errorf("decodeBatch(nil) = %q, want none", got)
	}
}

func TestDecodeBatchFallsBackToRawOnUnframedInput(t *testing.T) {
	got := decodeBatch([]byte{0x42})
	if len(got) != 1 || got[0][0] != 0x42 {
		t.Fatalf("decodeBatch(1 byte) = %v, want a single raw packet", got)
	}
}

func TestBase64EncodeRoundTrips(t *testing.T) {
	inputs := [][]byte{
		[]byte("short"),
		bytes.Repeat([]byte("x"), 200_000), // larger than the pooled buffer's default cap
		{},
	}
	for _, in := range inputs {
		out := base64Encode(in)
		got, err := base64.StdEncoding.DecodeString(out)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Equal(got, in) {
			t.Errorf("base64Encode round-trip mismatch for %d-byte input", len(in))
		}
	}
}

func TestBase64EncodeConcurrentCallsDontCorrupt(t *testing.T) {
	const n = 50
	done := make(chan bool, n)
	for i := 0; i < n; i++ {
		i := i
		go func() {
			data := bytes.Repeat([]byte{byte(i)}, 1000)
			out := base64Encode(data)
			decoded, err := base64.StdEncoding.DecodeString(out)
			done <- err == nil && bytes.Equal(decoded, data)
		}()
	}
	for i := 0; i < n; i++ {
		if !<-done {
			t.Errorf("concurrent base64Encode produced a corrupted result")
		}
	}
}

func TestGetStrAndGetFloatHandleMixedJSONNumberTypes(t *testing.T) {
	m := map[string]interface{}{
		"a": "text",
		"b": float64(42),
		"c": int64(7),
	}
	if got := getStr(m, "a"); got != "text" {
		t.Errorf("getStr(a) = %q, want text", got)
	}
	if got := getStr(m, "missing"); got != "" {
		t.Errorf("getStr(missing) = %q, want empty", got)
	}
	if got := getFloat(m, "b"); got != 42 {
		t.Errorf("getFloat(b) = %v, want 42", got)
	}
	if got := getFloat(nil, "x"); got != 0 {
		t.Errorf("getFloat(nil map) = %v, want 0", got)
	}
}
