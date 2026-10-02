package transport

import "fmt"

// WrapCodec applies the wire codec named by --codec; both ends of a tunnel must agree, or they can't decode each other's frames.
func WrapCodec(inner Transport, codec string) (Transport, error) {
	switch codec {
	case "", "legacy":
		return NewCompressedTransport(inner), nil
	case "batched":
		return NewBatchedTransport(inner), nil
	default:
		return nil, fmt.Errorf("unknown codec %q (want legacy|batched)", codec)
	}
}
