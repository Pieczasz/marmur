package main

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// A hand-built pktap_header (xnu bsd/net/pktap.h) + Ethernet + IPv4 + TCP with 39 payload bytes.
func TestDecodePktap(t *testing.T) {
	h := make([]byte, 156)
	le := binary.LittleEndian
	le.PutUint32(h[0:], 156)                // pth_length
	le.PutUint32(h[4:], 1)                  // PKT_REC_PACKET
	le.PutUint32(h[8:], 1)                  // DLT_EN10MB
	copy(h[0x0C:], "en0")                   // ifname
	le.PutUint32(h[0x24:], 0x2|0x4|0x20000) // out, delegated, socket
	le.PutUint32(h[0x2C:], 14)              // frame_pre_length
	le.PutUint32(h[0x34:], 98087)
	copy(h[0x38:], "nsurlsessiond")
	le.PutUint32(h[0x4C:], 2) // BE
	le.PutUint32(h[0x54:], 1084)
	copy(h[0x58:], "claude")
	le.PutUint32(h[0x6C:], 0xbef45f65)
	copy(h[0x7C:], []byte{0x4c, 0x4c, 0x44, 0x22, 0x55, 0x55, 0x31, 0x44, 0xa1, 0x14, 0x05, 0xa8, 0x5a, 0x46, 0x9c, 0xa7})
	copy(h[0x8C:], []byte{0x1f, 0xea, 0xf4, 0x1c, 0xe9, 0xaf, 0x39, 0xee, 0x86, 0xe4, 0xc3, 0x87, 0xed, 0xc5, 0xed, 0x44})

	eth := make([]byte, 14)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 20+32+39) // total length, TCP header with options = 32
	ip[9] = 6
	copy(ip[12:], []byte{10, 2, 0, 2})
	copy(ip[16:], []byte{160, 79, 104, 10})
	tcp := make([]byte, 32)
	binary.BigEndian.PutUint16(tcp[0:], 63352)
	binary.BigEndian.PutUint16(tcp[2:], 443)
	tcp[12] = 8 << 4 // data offset 8 words

	data := append(append(append(h, eth...), ip...), tcp...)
	var hdr layers.PktapV1
	ts := time.Unix(1792162951, 55757000)
	p, err := decodePktap(&hdr, data, gopacket.CaptureInfo{Timestamp: ts, CaptureLength: len(data)})
	if err != nil {
		t.Fatal(err)
	}

	checks := map[string][2]any{
		"iface":  {p.iface, "en0"},
		"proc":   {p.proc, "nsurlsessiond"},
		"pid":    {p.pid, uint32(98087)},
		"ecomm":  {p.ecomm, "claude"},
		"epid":   {p.epid, uint32(1084)},
		"dir":    {p.dir, DirectionOut},
		"svc":    {p.svc, "BE"},
		"flowid": {p.flowid, uint32(0xbef45f65)},
		"uuid":   {p.uuid, "4c4c4422-5555-3144-a114-05a85a469ca7"},
		"euuid":  {p.euuid, "1feaf41c-e9af-39ee-86e4-c387edc5ed44"},
		"proto":  {p.proto, TCP},
		"src":    {p.src, netip.MustParseAddrPort("10.2.0.2:63352")},
		"dst":    {p.dst, netip.MustParseAddrPort("160.79.104.10:443")},
		"length": {p.length, 39},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s: got %v, want %v", name, c[0], c[1])
		}
	}
}
