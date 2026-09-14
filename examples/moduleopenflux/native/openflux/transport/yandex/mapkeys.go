package yandex

import "encoding/binary"

// Дословно из openflux-server, где обе функции лежат в `volga.go` — транспорт Volga в модуль не
// портирован (см. README), но yandex.go зовёт их: `mapKeys` из диагностики `fetchDocInfo`,
// `decodeBatch` из batchMarker-ветки handleMessage (multi-stream).

func mapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func decodeBatch(decoded []byte) [][]byte {
	var packets [][]byte
	for len(decoded) >= 2 {
		ln := int(binary.BigEndian.Uint16(decoded[:2]))
		decoded = decoded[2:]
		if ln == 0 || len(decoded) < ln {
			break
		}
		packets = append(packets, decoded[:ln])
		decoded = decoded[ln:]
	}
	if len(packets) == 0 && len(decoded) > 0 {
		packets = append(packets, decoded)
	}
	return packets
}
