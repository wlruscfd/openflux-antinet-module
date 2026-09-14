package network

import (
	"fmt"
	"net"
	"strings"
)

// TCPChecksum / UDPChecksum are the same RFC 793/768 sum, differing only in the protocol number
// inside the pseudo-header. Separate bodies would drift on the first edit, so both are thin
// wrappers over L4Checksum; the names are kept so callers have nothing new to learn.
func TCPChecksum(tcpData []byte, srcIP, dstIP [4]byte) uint16 {
	return L4Checksum(tcpData, srcIP, dstIP, 6)
}

// UDPChecksum. Note: over IPv4 the UDP checksum field is optional (0 means "not computed"), but it
// must not be zeroed here — the exit node rewrites the packet's addresses and the sum covers them,
// so a surviving old value would be wrong and the receiver would drop the datagram silently.
func UDPChecksum(udpData []byte, srcIP, dstIP [4]byte) uint16 {
	return L4Checksum(udpData, srcIP, dstIP, 17)
}

func L4Checksum(l4Data []byte, srcIP, dstIP [4]byte, proto byte) uint16 {
	pseudoHeader := []byte{
		srcIP[0], srcIP[1], srcIP[2], srcIP[3],
		dstIP[0], dstIP[1], dstIP[2], dstIP[3],
		0, proto,
		0, 0,
	}

	tcpLen := len(l4Data)
	pseudoHeader[10] = byte(tcpLen >> 8)
	pseudoHeader[11] = byte(tcpLen & 0xff)

	all := make([]byte, 0, len(pseudoHeader)+tcpLen)
	all = append(all, pseudoHeader...)
	all = append(all, l4Data...)

	sum := uint32(0)
	for i := 0; i < len(all)-1; i += 2 {
		sum += uint32(all[i])<<8 | uint32(all[i+1])
	}
	if len(all)%2 == 1 {
		sum += uint32(all[len(all)-1]) << 8
	}

	for sum>>16 > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return uint16(^sum)
}

func IPChecksum(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xFFFF)
	sum += sum >> 16
	return uint16(^sum)
}

func ParsePacketInfo(data []byte) string {
	if len(data) < 20 {
		return fmt.Sprintf("short packet (%d bytes)", len(data))
	}
	srcIP := net.IP(data[12:16])
	dstIP := net.IP(data[16:20])
	protocol := data[9]
	ttl := data[8]
	totalLen := uint16(data[2])<<8 | uint16(data[3])

	if protocol == 6 && len(data) >= 40 {
		srcPort := uint16(data[20])<<8 | uint16(data[21])
		dstPort := uint16(data[22])<<8 | uint16(data[23])
		flags := data[33]
		seq := uint32(data[24])<<24 | uint32(data[25])<<16 | uint32(data[26])<<8 | uint32(data[27])
		ack := uint32(data[28])<<24 | uint32(data[29])<<16 | uint32(data[30])<<8 | uint32(data[31])
		window := uint16(data[34])<<8 | uint16(data[35])

		flagStr := ""
		if flags&0x02 != 0 {
			flagStr += "SYN "
		}
		if flags&0x10 != 0 {
			flagStr += "ACK "
		}
		if flags&0x01 != 0 {
			flagStr += "FIN "
		}
		if flags&0x04 != 0 {
			flagStr += "RST "
		}
		if flags&0x08 != 0 {
			flagStr += "PSH "
		}

		return fmt.Sprintf("TCP %s:%d -> %s:%d [%s] seq=%d ack=%d win=%d len=%d ttl=%d",
			srcIP, srcPort, dstIP, dstPort, strings.TrimSpace(flagStr), seq, ack, window, totalLen, ttl)
	}
	return fmt.Sprintf("IP proto=%d %s -> %s len=%d ttl=%d", protocol, srcIP, dstIP, totalLen, ttl)
}
