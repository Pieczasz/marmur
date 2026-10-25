//go:build darwin

package darwin

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/Pieczasz/marmur/internal/capture"
)

const (
	pktapHeaderLen   = 156
	pthFlagDirIn     = 0x1
	pthFlagDirOut    = 0x2
	pthFlagDelegated = 0x4
	pthFlagV2Header  = 0x80000

	// Offsets for PKTAP v1 structure
	// https://www.tcpdump.org/linktypes/LINKTYPE_PKTAP.html
	pktapHeaderLengthOffset     = 0x00
	pktapRecordTypeOffset       = 0x04
	pktapInterfaceOffset        = 0x0C
	pktapFlagsOffset            = 0x24
	pktapLinkHeaderLengthOffset = 0x2C
	pktapPIDOffset              = 0x34
	pktapProcessOffset          = 0x38
	pktapEffectivePIDOffset     = 0x54
	pktapEffectiveProcessOffset = 0x58
	pktapEffectiveUUIDOffset    = 0x8C
	pktapFlowIDOffset           = 0x6C
	pktapProcessUUIDOffset      = 0x7C

	noProcess = 0xFFFFFFFF // (uint32)(-1)
)

var (
	errTruncated         = errors.New("pktap: truncated")
	errNotIP             = errors.New("pktap: not IPv4/IPv6")
	errUnsupportedHeader = errors.New("pktap: unsupported header")
)

func decodePktap(data []byte, ts time.Time) (capture.PacketEvent, error) {
	if len(data) < pktapHeaderLen {
		return capture.PacketEvent{}, errTruncated
	}
	headerLen := binary.LittleEndian.Uint32(data[pktapHeaderLengthOffset:])

	if err := decodeHeader(headerLen, data); err != nil {
		return capture.PacketEvent{}, err
	}

	iface := cString(data[pktapInterfaceOffset : pktapInterfaceOffset+24])
	comm := cString(data[pktapProcessOffset : pktapProcessOffset+17])
	ev := &capture.PacketEvent{}

	decodeFlags(data, ev)
	if pid := binary.LittleEndian.Uint32(data[pktapPIDOffset:]); pid != noProcess {
		ev.PID, ev.Process, ev.ProcessUUID = pid, comm, uuidString(data[pktapProcessUUIDOffset:pktapProcessUUIDOffset+16])
	}

	ev.ObservedAt = ts.UTC()
	ev.FlowID = binary.LittleEndian.Uint32(data[pktapFlowIDOffset:])
	ev.Interface = iface

	rest := data[headerLen:]
	pre := int(binary.LittleEndian.Uint32(data[pktapLinkHeaderLengthOffset:]))
	if pre > len(rest) {
		return capture.PacketEvent{}, errTruncated
	}
	if err := decodeIP(ev, rest[pre:]); err != nil {
		return capture.PacketEvent{}, err
	}

	if epid := binary.LittleEndian.Uint32(data[pktapEffectivePIDOffset:]); epid != noProcess {
		ev.EffectivePID = epid
		ev.EffectiveProcess = cString(data[pktapEffectiveProcessOffset : pktapEffectiveProcessOffset+17])
		ev.EffectiveUUID = uuidString(data[pktapEffectiveUUIDOffset : pktapEffectiveUUIDOffset+16])
	}

	return *ev, nil
}

func decodeFlags(data []byte, ev *capture.PacketEvent) {
	flags := binary.LittleEndian.Uint32(data[pktapFlagsOffset:])
	switch {
	case flags&pthFlagDirIn != 0:
		ev.Direction = capture.DirectionIn
	case flags&pthFlagDirOut != 0:
		ev.Direction = capture.DirectionOut
	}
	ev.Delegated = flags&pthFlagDelegated != 0
}

func decodeHeader(headerLen uint32, data []byte) error {
	flags := binary.LittleEndian.Uint32(data[pktapFlagsOffset:])

	if headerLen < pktapHeaderLen {
		return errUnsupportedHeader
	}
	if int(headerLen) > len(data) {
		return errTruncated
	}
	if binary.LittleEndian.Uint32(data[pktapRecordTypeOffset:]) != 1 {
		return errUnsupportedHeader
	}
	if flags&pthFlagV2Header != 0 {
		return errUnsupportedHeader
	}

	return nil
}

func decodeIP(ev *capture.PacketEvent, ip []byte) error {
	if len(ip) == 0 {
		return errNotIP
	}

	ipVersion := ip[0] >> 4
	switch ipVersion {
	case 4:
		return decodeIPv4(ev, ip)
	case 6:
		return decodeIPv6(ev, ip)
	default:
		return errNotIP
	}
}

func decodeIPv4(ev *capture.PacketEvent, ip []byte) error {
	if len(ip) < 20 {
		return errTruncated
	}
	ihl := int(ip[0]&0x0F) * 4
	if ihl < 20 || ihl > len(ip) {
		return errTruncated
	}

	payload := int(binary.BigEndian.Uint16(ip[2:4])) - ihl
	src := netip.AddrFrom4([4]byte(ip[12:16]))
	dst := netip.AddrFrom4([4]byte(ip[16:20]))

	ev.Protocol = decodeIPv4Protocol(ip[9])
	return decodeTransport(ev, ip[ihl:], payload, src, dst)
}

func decodeIPv4Protocol(n byte) capture.Protocol {
	switch n {
	case 1:
		return capture.ICMP
	case 6:
		return capture.TCP
	case 17:
		return capture.UDP
	case 50:
		return capture.ESP
	default:
		return ""
	}
}

func decodeIPv6(ev *capture.PacketEvent, ip []byte) error {
	if len(ip) < 40 {
		return errTruncated
	}

	payload := int(binary.BigEndian.Uint16(ip[4:6]))
	src := netip.AddrFrom16([16]byte(ip[8:24]))
	dst := netip.AddrFrom16([16]byte(ip[24:40]))

	ev.Protocol = decodeIPv6Protocol(ip[6])
	return decodeTransport(ev, ip[40:], payload, src, dst)
}

func decodeIPv6Protocol(n byte) capture.Protocol {
	switch n {
	case 6:
		return capture.TCP
	case 17:
		return capture.UDP
	case 58:
		return capture.ICMPv6
	default:
		return ""
	}
}

func decodeTransport(ev *capture.PacketEvent, l4 []byte, payload int, src, dst netip.Addr) error {
	ev.Src = netip.AddrPortFrom(src, 0)
	ev.Dst = netip.AddrPortFrom(dst, 0)
	ev.Length = max(payload, 0)

	switch ev.Protocol {
	case capture.TCP:
		return decodeTCP(ev, l4, src, dst)
	case capture.UDP:
		return decodeUDP(ev, l4, src, dst)
	default:
		return nil
	}
}

func decodeTCP(ev *capture.PacketEvent, l4 []byte, src, dst netip.Addr) error {
	if len(l4) < 13 {
		return errTruncated
	}

	ev.Src = netip.AddrPortFrom(src, binary.BigEndian.Uint16(l4[0:2]))
	ev.Dst = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(l4[2:4]))
	ev.Length = max(ev.Length-(int(l4[12]>>4)*4), 0)
	return nil
}

func decodeUDP(ev *capture.PacketEvent, l4 []byte, src, dst netip.Addr) error {
	if len(l4) < 8 {
		return errTruncated
	}

	ev.Src = netip.AddrPortFrom(src, binary.BigEndian.Uint16(l4[0:2]))
	ev.Dst = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(l4[2:4]))
	ev.Length = max(int(binary.BigEndian.Uint16(l4[4:6]))-8, 0)
	return nil
}

func cString(cLikeString []byte) string {
	if firstZero := bytes.IndexByte(cLikeString, 0); firstZero >= 0 {
		cLikeString = cLikeString[:firstZero]
	}
	return string(cLikeString)
}

func uuidString(b []byte) string {
	if allZero(b) {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func allZero(b []byte) bool {
	return bytes.Equal(b, make([]byte, 16))
}
