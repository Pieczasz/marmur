package main

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func TestGenerateHoldsTheRequestedRate(t *testing.T) {
	for _, pps := range []int{5000, 20000, 50000} {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		sent, err := generate(ctx, pps, 49998)
		cancel()
		if err != nil {
			t.Fatalf("%d pps: %v", pps, err)
		}
		want := pps / 2
		if sent < want*90/100 || sent > want*105/100 {
			t.Errorf("%d pps for 500ms: sent %d, want about %d", pps, sent, want)
		}
	}
}

func TestMatchPrefersSameLengthOverCloserTimestamp(t *testing.T) {
	base := time.Unix(1792162951, 0)
	src, dst := netip.MustParseAddrPort("10.2.0.2:5000"), netip.MustParseAddrPort("1.1.1.1:443")
	mk := func(us int, length int) pkt {
		return pkt{ts: base.Add(time.Duration(us) * time.Microsecond), iface: "utun6", dir: DirectionOut, src: src, dst: dst, length: length}
	}
	// Two packets of one flow 20µs apart; tcpdump's timestamps are shifted so the
	// closest candidate for each gopacket packet is the *other* packet.
	gp := []pkt{mk(0, 100), mk(20, 1400)}
	td := []pkt{mk(15, 1400), mk(-5, 100)}

	pairs := matchPackets(gp, td, 5*time.Millisecond)
	if len(pairs) != 2 {
		t.Fatalf("want 2 pairs, got %d", len(pairs))
	}
	for _, p := range pairs {
		if gp[p.g].length != td[p.t].length {
			t.Errorf("cross-matched: gopacket len %d with tcpdump len %d", gp[p.g].length, td[p.t].length)
		}
	}
}

func TestMatchIgnoresPacketsOutsideTheWindow(t *testing.T) {
	base := time.Unix(1792162951, 0)
	src, dst := netip.MustParseAddrPort("10.2.0.2:5000"), netip.MustParseAddrPort("1.1.1.1:443")
	gp := []pkt{{ts: base, iface: "en0", dir: DirectionOut, src: src, dst: dst}}
	td := []pkt{{ts: base.Add(10 * time.Millisecond), iface: "en0", dir: DirectionOut, src: src, dst: dst}}
	if pairs := matchPackets(gp, td, 5*time.Millisecond); len(pairs) != 0 {
		t.Fatalf("want no match outside 5ms, got %d", len(pairs))
	}
}

func TestDecodeNormalizesMissingProcess(t *testing.T) {
	h := make([]byte, 156)
	le := binary.LittleEndian
	le.PutUint32(h[0:], 156)
	le.PutUint32(h[4:], 1)
	le.PutUint32(h[8:], 0) // DLT_NULL (utun)
	copy(h[0x0C:], "utun6")
	le.PutUint32(h[0x24:], 0x2)
	le.PutUint32(h[0x2C:], 4)
	le.PutUint32(h[0x34:], noPID) // pth_pid = -1
	copy(h[0x38:], "syspolicyd")  // pid -1 wins: the packet is unattributed
	le.PutUint32(h[0x54:], noPID) // pth_epid = -1

	ip := make([]byte, 28)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], 28)
	ip[9] = 17
	copy(ip[12:], []byte{10, 2, 0, 2})
	copy(ip[16:], []byte{17, 248, 179, 230})
	binary.BigEndian.PutUint16(ip[20:], 58966)
	binary.BigEndian.PutUint16(ip[22:], 443)
	binary.BigEndian.PutUint16(ip[24:], 8)

	data := append(append(h, 0, 0, 0, 2), ip...)
	var hdr layers.PktapV1
	p, err := decodePktap(&hdr, data, gopacket.CaptureInfo{Timestamp: time.Unix(1, 0), CaptureLength: len(data), Length: len(data)})
	if err != nil {
		t.Fatal(err)
	}
	if p.pid != 0 || p.proc != "" {
		t.Errorf("pid -1 must mean no process, got %s:%d", p.proc, p.pid)
	}
	if p.epid != 0 || p.ecomm != "" {
		t.Errorf("epid -1 must mean no effective process, got %s:%d", p.ecomm, p.epid)
	}
	if p.ipVer != 4 || p.ipLenField != 28 || p.wireLen != 28 {
		t.Errorf("length diagnostics: ipVer %d ipLenField %d wireLen %d", p.ipVer, p.ipLenField, p.wireLen)
	}
}
