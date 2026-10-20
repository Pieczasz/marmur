package collector

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"
)

const (
	fxFlagIn        = 0x1
	fxFlagOut       = 0x2
	fxFlagDelegated = 0x4
	fxFlagV2        = 0x80000
	fxNoProcess     = 0xFFFFFFFF
)

var (
	fxTS    = time.Unix(1792162951, 55757000)
	fxUUID  = [16]byte{0x4c, 0x4c, 0x44, 0x22, 0x55, 0x55, 0x31, 0x44, 0xa1, 0x14, 0x05, 0xa8, 0x5a, 0x46, 0x9c, 0xa7}
	fxEUUID = [16]byte{0x1f, 0xea, 0xf4, 0x1c, 0xe9, 0xaf, 0x39, 0xee, 0x86, 0xe4, 0xc3, 0x87, 0xed, 0xc5, 0xed, 0x44}
)

const (
	fxUUIDText  = "4c4c4422-5555-3144-a114-05a85a469ca7"
	fxEUUIDText = "1feaf41c-e9af-39ee-86e4-c387edc5ed44"
)

// fxRecord builds a pktap_header. Zero values mean: record type 1, length 156.
type fxRecord struct {
	recType, hdrLen uint32
	dlt             uint32
	ifname          string
	flags           uint32
	pre             uint32
	pid             uint32
	comm            string
	epid            uint32
	ecomm           string
	flowid          uint32
	uuid, euuid     [16]byte
}

func (r fxRecord) build(link, ip []byte) []byte {
	h := make([]byte, 156)
	le := binary.LittleEndian
	if r.hdrLen == 0 {
		r.hdrLen = 156
	}
	if r.recType == 0 {
		r.recType = 1
	}
	le.PutUint32(h[0x00:], r.hdrLen)
	le.PutUint32(h[0x04:], r.recType)
	le.PutUint32(h[0x08:], r.dlt)
	copy(h[0x0C:0x24], r.ifname)
	le.PutUint32(h[0x24:], r.flags)
	le.PutUint32(h[0x2C:], r.pre)
	le.PutUint32(h[0x34:], r.pid)
	copy(h[0x38:0x38+17], r.comm)
	le.PutUint32(h[0x54:], r.epid)
	copy(h[0x58:0x58+17], r.ecomm)
	le.PutUint32(h[0x6C:], r.flowid)
	copy(h[0x7C:], r.uuid[:])
	copy(h[0x8C:], r.euuid[:])
	return append(append(h, link...), ip...)
}

var (
	fxEthernet = make([]byte, 14)   // DLT_EN10MB, frame_pre_length 14
	fxNullLink = []byte{2, 0, 0, 0} // DLT_NULL (utun, lo0), frame_pre_length 4
)

func fxIPv4(src, dst string, proto byte, l4 []byte, totalLen int) []byte {
	b := make([]byte, 20)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(totalLen))
	b[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	return append(b, l4...)
}

func fxIPv6(src, dst string, next byte, l4 []byte, payloadLen int) []byte {
	b := make([]byte, 40)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(payloadLen))
	b[6] = next
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(b[8:], s[:])
	copy(b[24:], d[:])
	return append(b, l4...)
}

// fxTCP returns a TCP header of hdrLen bytes (20..60). Payload bytes are not included:
// lengths come from the IP header, as with a snaplen cut.
func fxTCP(sport, dport uint16, hdrLen int) []byte {
	b := make([]byte, hdrLen)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	b[12] = byte(hdrLen/4) << 4
	return b
}

func fxUDP(sport, dport uint16, payload int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:], sport)
	binary.BigEndian.PutUint16(b[2:], dport)
	binary.BigEndian.PutUint16(b[4:], uint16(8+payload))
	return b
}

func TestDecodePktap(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want PacketEvent
	}{
		{
			name: "en0 out TCP with options, all process fields",
			data: fxRecord{dlt: 1, ifname: "en0", flags: fxFlagOut | 0x20000, pre: 14, pid: 1084, comm: "claude",
				epid: 1084, ecomm: "claude", flowid: 0xbef45f65, uuid: fxUUID}.
				build(fxEthernet, fxIPv4("10.2.0.2", "160.79.104.10", 6, fxTCP(63352, 443, 32), 20+32+39)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "en0", Direction: DirectionOut,
				Process: "claude", PID: 1084, ProcessUUID: fxUUIDText,
				EffectiveProcess: "claude", EffectivePID: 1084, FlowID: 0xbef45f65,
				Protocol: TCP, Src: ap("10.2.0.2:63352"), Dst: ap("160.79.104.10:443"), Length: 39,
			},
		},
		{
			name: "utun in UDP after a 4-byte DLT_NULL header",
			data: fxRecord{dlt: 0, ifname: "utun6", flags: fxFlagIn, pre: 4, pid: 98087, comm: "claude", uuid: fxUUID}.
				build(fxNullLink, fxIPv4("160.79.104.10", "10.2.0.2", 17, fxUDP(443, 51690, 448), 20+8+448)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "utun6", Direction: DirectionIn,
				Process: "claude", PID: 98087, ProcessUUID: fxUUIDText,
				Protocol: UDP, Src: ap("160.79.104.10:443"), Dst: ap("10.2.0.2:51690"), Length: 448,
			},
		},
		{
			name: "delegated DNS lookup: mDNSResponder on behalf of curl",
			data: fxRecord{dlt: 0, ifname: "utun6", flags: fxFlagOut | fxFlagDelegated, pre: 4,
				pid: 688, comm: "mDNSResponder", uuid: fxUUID, epid: 3279, ecomm: "curl", euuid: fxEUUID}.
				build(fxNullLink, fxIPv4("10.2.0.2", "10.2.0.1", 17, fxUDP(55615, 53, 38), 20+8+38)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "utun6", Direction: DirectionOut,
				Process: "mDNSResponder", PID: 688, ProcessUUID: fxUUIDText,
				EffectiveProcess: "curl", EffectivePID: 3279, EffectiveUUID: fxEUUIDText, Delegated: true,
				Protocol: UDP, Src: ap("10.2.0.2:55615"), Dst: ap("10.2.0.1:53"), Length: 38,
			},
		},
		{
			name: "pid and epid -1 mean no process, packet still returned",
			data: fxRecord{dlt: 1, ifname: "en0", flags: fxFlagIn, pre: 14, pid: fxNoProcess, epid: fxNoProcess, uuid: fxUUID}.
				build(fxEthernet, fxIPv6("fe80::c6eb:39ff:fe51:14f2", "ff02::1", 58, make([]byte, 8), 136)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "en0", Direction: DirectionIn,
				Protocol: ICMPv6, Src: addrOnly("fe80::c6eb:39ff:fe51:14f2"), Dst: addrOnly("ff02::1"), Length: 136,
			},
		},
		{
			name: "16-character name fills comm exactly",
			data: fxRecord{dlt: 0, ifname: "utun6", flags: fxFlagIn, pre: 4, pid: 70007, comm: "Google Chrome He"}.
				build(fxNullLink, fxIPv4("18.65.39.60", "10.2.0.2", 6, fxTCP(443, 55885, 32), 52)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "utun6", Direction: DirectionIn,
				Process: "Google Chrome He", PID: 70007,
				Protocol: TCP, Src: ap("18.65.39.60:443"), Dst: ap("10.2.0.2:55885"), Length: 0,
			},
		},
		{
			name: "snaplen cut payload: length still from the IP header",
			data: fxRecord{dlt: 1, ifname: "en0", flags: fxFlagIn, pre: 14, pid: 59292, comm: "zen"}.
				build(fxEthernet, fxIPv4("34.107.243.93", "192.168.178.167", 6, fxTCP(443, 55686, 20), 20+20+1400)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "en0", Direction: DirectionIn,
				Process: "zen", PID: 59292,
				Protocol: TCP, Src: ap("34.107.243.93:443"), Dst: ap("192.168.178.167:55686"), Length: 1400,
			},
		},
		{
			name: "IPv6 UDP on loopback",
			data: fxRecord{dlt: 0, ifname: "lo0", flags: fxFlagOut, pre: 4, pid: 688, comm: "mDNSResponder"}.
				build(fxNullLink, fxIPv6("fe80::a8ab:c9ff:fe4f:79de", "ff02::fb", 17, fxUDP(5353, 5353, 63), 8+63)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "lo0", Direction: DirectionOut,
				Process: "mDNSResponder", PID: 688,
				Protocol: UDP, Src: ap("[fe80::a8ab:c9ff:fe4f:79de]:5353"), Dst: ap("[ff02::fb]:5353"), Length: 63,
			},
		},
		{
			name: "ICMP has no ports, length is the IP payload",
			data: fxRecord{dlt: 1, ifname: "en0", flags: fxFlagOut, pre: 14, pid: 555, comm: "ping"}.
				build(fxEthernet, fxIPv4("10.0.0.1", "8.8.8.8", 1, make([]byte, 8), 20+64)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "en0", Direction: DirectionOut,
				Process: "ping", PID: 555,
				Protocol: ICMP, Src: addrOnly("10.0.0.1"), Dst: addrOnly("8.8.8.8"), Length: 64,
			},
		},
		{
			name: "ESP from the VPN client",
			data: fxRecord{dlt: 1, ifname: "en0", flags: fxFlagOut, pre: 14, pid: 65632, comm: "ch.protonvpn.mac"}.
				build(fxEthernet, fxIPv4("192.168.178.167", "62.169.136.103", 50, make([]byte, 8), 20+108)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "en0", Direction: DirectionOut,
				Process: "ch.protonvpn.mac", PID: 65632,
				Protocol: ESP, Src: addrOnly("192.168.178.167"), Dst: addrOnly("62.169.136.103"), Length: 108,
			},
		},
		{
			name: "IPv6 hop-by-hop header is not walked: unknown protocol, IPv6 payload length",
			data: fxRecord{dlt: 1, ifname: "en0", flags: fxFlagOut, pre: 14}.
				build(fxEthernet, fxIPv6("fe80::1", "ff02::16", 0, make([]byte, 8), 36)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "en0", Direction: DirectionOut,
				Src: addrOnly("fe80::1"), Dst: addrOnly("ff02::16"), Length: 36,
			},
		},
		{
			name: "IP length smaller than the headers never gives a negative length",
			data: fxRecord{dlt: 1, ifname: "en0", flags: fxFlagOut, pre: 14, pid: 1, comm: "a"}.
				build(fxEthernet, fxIPv4("10.0.0.1", "10.0.0.2", 6, fxTCP(1, 2, 20), 0)),
			want: PacketEvent{
				ObservedAt: fxTS.UTC(), Interface: "en0", Direction: DirectionOut,
				Process: "a", PID: 1,
				Protocol: TCP, Src: ap("10.0.0.1:1"), Dst: ap("10.0.0.2:2"), Length: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodePktap(tt.data, fxTS)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			assertPacketEvent(t, tt.want, got)
			assertPktapExtras(t, tt.want, got)
		})
	}
}

func TestDecodePktapErrors(t *testing.T) {
	validIP := fxIPv4("10.0.0.1", "10.0.0.2", 17, fxUDP(1, 2, 0), 28)
	short := fxRecord{dlt: 1, ifname: "en0", pre: 14}.build(fxEthernet, validIP)[:100]
	lying := fxRecord{hdrLen: 400, dlt: 1, ifname: "en0", pre: 14}.build(fxEthernet, validIP)

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, errTruncated},
		{"shorter than the 156-byte header", short, errTruncated},
		{"pth_length larger than the record", lying, errTruncated},
		{"pth_length below 156", fxRecord{hdrLen: 100}.build(nil, nil), errUnsupportedHeader},
		{"record type is not a packet", fxRecord{recType: 2}.build(nil, nil), errUnsupportedHeader},
		{"v2 header", fxRecord{flags: fxFlagV2, pre: 4}.build(fxNullLink, validIP), errUnsupportedHeader},
		{"link header longer than the rest", fxRecord{dlt: 1, pre: 14}.build([]byte{1, 2, 3}, nil), errTruncated},
		{"ARP is not IP", fxRecord{dlt: 1, pre: 14}.build(fxEthernet, []byte{0x00, 0x01, 0x08, 0x00, 6, 4, 0, 1}), errNotIP},
		{"IPv4 header cut", fxRecord{dlt: 1, pre: 14}.build(fxEthernet, validIP[:10]), errTruncated},
		{"IPv6 header cut", fxRecord{dlt: 1, pre: 14}.build(fxEthernet, fxIPv6("::1", "::1", 17, nil, 8)[:30]), errTruncated},
		{"TCP ports cut", fxRecord{dlt: 1, pre: 14}.build(fxEthernet, fxIPv4("10.0.0.1", "10.0.0.2", 6, []byte{0, 1}, 40)), errTruncated},
		{"UDP header cut", fxRecord{dlt: 1, pre: 14}.build(fxEthernet, fxIPv4("10.0.0.1", "10.0.0.2", 17, []byte{0, 1, 0, 2}, 28)), errTruncated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodePktap(tt.data, fxTS)
			if !errors.Is(err, tt.want) {
				t.Fatalf("want %v, got err=%v event=%+v", tt.want, err, got)
			}
		})
	}
}

func FuzzDecodePktap(f *testing.F) {
	f.Add(fxRecord{dlt: 1, ifname: "en0", flags: fxFlagOut, pre: 14, pid: 1, comm: "a"}.
		build(fxEthernet, fxIPv4("10.0.0.1", "10.0.0.2", 6, fxTCP(1, 2, 20), 40)))
	f.Add(fxRecord{dlt: 0, ifname: "utun6", flags: fxFlagIn, pre: 4}.
		build(fxNullLink, fxIPv6("::1", "::2", 17, fxUDP(1, 2, 3), 11)))
	f.Add(fxRecord{pre: 0xFFFFFFFF}.build(nil, nil))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		ev, err := decodePktap(data, fxTS)
		if err != nil {
			return
		}
		if !ev.Src.Addr().IsValid() || !ev.Dst.Addr().IsValid() {
			t.Errorf("event without valid addresses: %+v", ev)
		}
		if ev.Length < 0 {
			t.Errorf("negative length %d", ev.Length)
		}
		if ev.Direction != "" && ev.Direction != DirectionIn && ev.Direction != DirectionOut {
			t.Errorf("unexpected direction %q", ev.Direction)
		}
	})
}

func assertPktapExtras(t *testing.T, exp, act PacketEvent) {
	t.Helper()
	if act.EffectiveProcess != exp.EffectiveProcess {
		t.Errorf("EffectiveProcess mismatch: expected %q, got %q", exp.EffectiveProcess, act.EffectiveProcess)
	}
	if act.EffectivePID != exp.EffectivePID {
		t.Errorf("EffectivePID mismatch: expected %d, got %d", exp.EffectivePID, act.EffectivePID)
	}
	if act.EffectiveUUID != exp.EffectiveUUID {
		t.Errorf("EffectiveUUID mismatch: expected %q, got %q", exp.EffectiveUUID, act.EffectiveUUID)
	}
	if act.Delegated != exp.Delegated {
		t.Errorf("Delegated mismatch: expected %v, got %v", exp.Delegated, act.Delegated)
	}
	if act.FlowID != exp.FlowID {
		t.Errorf("FlowID mismatch: expected %#x, got %#x", exp.FlowID, act.FlowID)
	}
}
