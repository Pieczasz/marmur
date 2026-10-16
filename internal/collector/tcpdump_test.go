package collector

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Contract for parseTcpdumpLine.
//
// Input is one stdout line of:
//
//	/usr/sbin/tcpdump -i pktap,all -n -q -tt -l -k INPDU
//
//	-q       short tail: "tcp 39", "UDP, length 448", no decoded DNS/mDNS contents
//	-tt      Unix seconds.microseconds, so no date or time zone guessing
//	-k INPDU interface, process name, PID, direction, process UUID
//
// Shape:
//
//	<epoch> [(<metadata>)] IP|IP6 <src> > <dst>: <tail>
//
// Rules:
//   - Only IPv4/IPv6 packet lines produce an event. Everything else returns ok=false:
//     tcpdump banners, stats, ARP, blank or truncated lines, HH:MM:SS timestamps.
//   - The metadata block is optional. Fields are separated by ", ". The block ends at
//     ") IP " or ") IP6 ", so a process name may contain parentheses.
//   - The first field is the interface when it has no space and is not "in"/"out".
//   - "proc NAME:PID:UUID" or "proc NAME:PID". The UUID is present when the last
//     colon part is a 36-character UUID. PID is the part before it. The name is
//     everything before the PID and may contain dots, spaces and colons.
//   - A proc field with a bad PID (not a number, or above uint32) leaves Process,
//     PID and ProcessUUID empty. The packet is still returned.
//   - "eproc ...", "svc ...", "flowid ...", flags like "so"/"ka" and unknown fields are ignored.
//   - "in"/"out" set Direction. No direction field leaves it empty.
//   - Addresses: the whole token is the address when it parses as one (ICMP, ESP).
//     Otherwise, the port is the part after the last dot. Ports above 65535 reject the line.
//   - Tail: "tcp N" → TCP; "UDP, length N" → UDP; "ICMP ..." → ICMP; "ICMP6, ..." → ICMPv6;
//     "ESP(...)" → "ESP". Length is N from "tcp N" or the trailing "length N".
//     Any other tail keeps Protocol empty and still reads a trailing "length N".
//     A length that is not a non-negative integer stays 0.

const (
	claudeUUID  = "4c4c4422-5555-3144-a114-05a85a469ca7"
	nodeUUID    = "1feaf41c-e9af-39ee-86e4-c387edc5ed44"
	protonUUID  = "fd53e1b1-e66c-3185-8792-43c8f30383e5"
	discordUUID = "4c4c446e-5555-3144-a1ec-7fe909e75873"
	mdnsUUID    = "ec2d328a-d72e-3add-acce-747ad3f22827"
	mdnsEUUID   = "979c0a62-49fe-4739-bdcb-cac584ac832d"
	kernelUUID  = "00000000-0000-0000-0000-000000000000"
)

const tsText = "1792161257.014279"

var tsTime = time.Unix(1792161257, 14279000).UTC()

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func addrOnly(s string) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr(s), 0) }

func TestParseTcpdumpLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want PacketEvent
	}{
		{
			name: "TCP keepalive out on VPN tunnel names the real app, extra -k A fields ignored",
			line: tsText + " (utun6, proc claude:1084:" + claudeUUID + ", svc BE, out, ka, so, flowid 0xbef45f65, ttag 0x0, dlt 0x0, cmpgc 0x0) IP 10.2.0.2.63352 > 160.79.104.10.443: tcp 0",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "utun6",
				Process:     "claude",
				PID:         1084,
				ProcessUUID: claudeUUID,
				Direction:   DirectionOut,
				Protocol:    TCP,
				Src:         ap("10.2.0.2:63352"),
				Dst:         ap("160.79.104.10:443"),
				Length:      0,
			},
		},
		{
			name: "minimal INPDU block",
			line: tsText + " (utun6, proc claude:1084:" + claudeUUID + ", out) IP 10.2.0.2.63352 > 160.79.104.10.443: tcp 0",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "utun6",
				Process:     "claude",
				PID:         1084,
				ProcessUUID: claudeUUID,
				Direction:   DirectionOut,
				Protocol:    TCP,
				Src:         ap("10.2.0.2:63352"),
				Dst:         ap("160.79.104.10:443"),
			},
		},
		{
			name: "TCP data in with eproc, eproc ignored",
			line: tsText + " (utun6, proc node:96877:" + nodeUUID + ", eproc node:96877:, svc BE, in, so, flowid 0xb7a8d17a, ttag 0x0, dlt 0x0, cmpgc 0x0) IP 34.225.159.174.443 > 10.2.0.2.62982: tcp 39",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "utun6",
				Process:     "node",
				PID:         96877,
				ProcessUUID: nodeUUID,
				Direction:   DirectionIn,
				Protocol:    TCP,
				Src:         ap("34.225.159.174:443"),
				Dst:         ap("10.2.0.2:62982"),
				Length:      39,
			},
		},
		{
			name: "VPN client on Wi-Fi, dotted name, UDP",
			line: tsText + " (en0, proc ch.protonvpn.mac:65632:" + protonUUID + ", svc BE, out, so, flowid 0xa1bc790b, ttag 0x0, dlt 0x1, cmpgc 0x0) IP 192.168.178.167.62125 > 62.169.136.103.500: UDP, length 60",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "en0",
				Process:     "ch.protonvpn.mac",
				PID:         65632,
				ProcessUUID: protonUUID,
				Direction:   DirectionOut,
				Protocol:    UDP,
				Src:         ap("192.168.178.167:62125"),
				Dst:         ap("62.169.136.103:500"),
				Length:      60,
			},
		},
		{
			name: "process name with a space",
			line: tsText + " (utun6, proc Discord Helper:76591:" + discordUUID + ", eproc Discord Helper:76591:, svc BE, in, so) IP 162.159.135.234.443 > 10.2.0.2.62379: tcp 251",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "utun6",
				Process:     "Discord Helper",
				PID:         76591,
				ProcessUUID: discordUUID,
				Direction:   DirectionIn,
				Protocol:    TCP,
				Src:         ap("162.159.135.234:443"),
				Dst:         ap("10.2.0.2:62379"),
				Length:      251,
			},
		},
		{
			name: "process name with parentheses",
			line: tsText + " (utun6, proc Discord Helper (Renderer):81623:" + discordUUID + ", out) IP 10.2.0.2.64603 > 162.159.135.232.443: UDP, length 1200",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "utun6",
				Process:     "Discord Helper (Renderer)",
				PID:         81623,
				ProcessUUID: discordUUID,
				Direction:   DirectionOut,
				Protocol:    UDP,
				Src:         ap("10.2.0.2:64603"),
				Dst:         ap("162.159.135.232:443"),
				Length:      1200,
			},
		},
		{
			name: "NPD block: no interface, no UUID, PID is the last part",
			line: tsText + " (proc ch.protonvpn.mac:74422, in) IP 192.0.2.1.443 > 198.51.100.10.51690: UDP, length 448",
			want: PacketEvent{
				ObservedAt: tsTime,
				Process:    "ch.protonvpn.mac",
				PID:        74422,
				Direction:  DirectionIn,
				Protocol:   UDP,
				Src:        ap("192.0.2.1:443"),
				Dst:        ap("198.51.100.10:51690"),
				Length:     448,
			},
		},
		{
			name: "name with colons and a UUID",
			line: tsText + " (en0, proc com.example:helper:4242:" + claudeUUID + ", out) IP 10.0.0.2.5000 > 10.0.0.3.80: tcp 1",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "en0",
				Process:     "com.example:helper",
				PID:         4242,
				ProcessUUID: claudeUUID,
				Direction:   DirectionOut,
				Protocol:    TCP,
				Src:         ap("10.0.0.2:5000"),
				Dst:         ap("10.0.0.3:80"),
				Length:      1,
			},
		},
		{
			name: "name with colons and no UUID",
			line: tsText + " (en0, proc com.example:helper:4242, out) IP 10.0.0.2.5000 > 10.0.0.3.80: tcp 1",
			want: PacketEvent{
				ObservedAt: tsTime,
				Interface:  "en0",
				Process:    "com.example:helper",
				PID:        4242,
				Direction:  DirectionOut,
				Protocol:   TCP,
				Src:        ap("10.0.0.2:5000"),
				Dst:        ap("10.0.0.3:80"),
				Length:     1,
			},
		},
		{
			name: "kernel PID 0 is a real PID",
			line: tsText + " (en0, proc kernel_task:0:" + kernelUUID + ", out) IP 192.168.178.167.5000 > 192.168.178.1.53: UDP, length 30",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "en0",
				Process:     "kernel_task",
				PID:         0,
				ProcessUUID: kernelUUID,
				Direction:   DirectionOut,
				Protocol:    UDP,
				Src:         ap("192.168.178.167:5000"),
				Dst:         ap("192.168.178.1:53"),
				Length:      30,
			},
		},
		{
			name: "no proc field: router advertisement still counted, ICMPv6 has no ports",
			line: tsText + " (en0, svc BE, in, flowid 0x0, ttag 0x0, dlt 0x1, cmpgc 0x0) IP6 fe80::c6eb:39ff:fe51:14f2 > ff02::1: ICMP6, router advertisement, length 136",
			want: PacketEvent{
				ObservedAt: tsTime,
				Interface:  "en0",
				Direction:  DirectionIn,
				Protocol:   ICMPv6,
				Src:        addrOnly("fe80::c6eb:39ff:fe51:14f2"),
				Dst:        addrOnly("ff02::1"),
				Length:     136,
			},
		},
		{
			name: "eproc alone is not a proc",
			line: tsText + " (lo0, eproc :688:" + mdnsEUUID + ", svc CTL, out, so) IP6 fe80::a8ab:c9ff:fe4f:79de.5353 > ff02::fb.5353: UDP, length 63",
			want: PacketEvent{
				ObservedAt: tsTime,
				Interface:  "lo0",
				Direction:  DirectionOut,
				Protocol:   UDP,
				Src:        ap("[fe80::a8ab:c9ff:fe4f:79de]:5353"),
				Dst:        ap("[ff02::fb]:5353"),
				Length:     63,
			},
		},
		{
			name: "mDNSResponder with empty-name eproc, IPv6 UDP on loopback",
			line: tsText + " (lo0, proc mDNSResponder:688:" + mdnsUUID + ", eproc :688:" + mdnsEUUID + ", svc CTL, out, so, flowid 0x9e0d82f1, ttag 0x0, dlt 0x0, cmpgc 0x0) IP6 fe80::a8ab:c9ff:fe4f:79de.5353 > ff02::fb.5353: UDP, length 63",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "lo0",
				Process:     "mDNSResponder",
				PID:         688,
				ProcessUUID: mdnsUUID,
				Direction:   DirectionOut,
				Protocol:    UDP,
				Src:         ap("[fe80::a8ab:c9ff:fe4f:79de]:5353"),
				Dst:         ap("[ff02::fb]:5353"),
				Length:      63,
			},
		},
		{
			name: "IPv6 TCP with ports",
			line: tsText + " (en0, proc curl:700:" + claudeUUID + ", out) IP6 2001:db8::5.51000 > 2001:db8::1.443: tcp 10",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "en0",
				Process:     "curl",
				PID:         700,
				ProcessUUID: claudeUUID,
				Direction:   DirectionOut,
				Protocol:    TCP,
				Src:         ap("[2001:db8::5]:51000"),
				Dst:         ap("[2001:db8::1]:443"),
				Length:      10,
			},
		},
		{
			name: "ICMP echo has no ports",
			line: tsText + " (en0, proc ping:555:" + claudeUUID + ", out) IP 10.0.0.1 > 8.8.8.8: ICMP echo request, id 1, seq 1, length 64",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "en0",
				Process:     "ping",
				PID:         555,
				ProcessUUID: claudeUUID,
				Direction:   DirectionOut,
				Protocol:    ICMP,
				Src:         addrOnly("10.0.0.1"),
				Dst:         addrOnly("8.8.8.8"),
				Length:      64,
			},
		},
		{
			name: "ESP from the VPN client",
			line: tsText + " (en0, proc ch.protonvpn.mac:65632:" + protonUUID + ", out) IP 192.168.178.167 > 62.169.136.103: ESP(spi=0x00001234,seq=0x7), length 108",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "en0",
				Process:     "ch.protonvpn.mac",
				PID:         65632,
				ProcessUUID: protonUUID,
				Direction:   DirectionOut,
				Protocol:    Protocol("ESP"),
				Src:         addrOnly("192.168.178.167"),
				Dst:         addrOnly("62.169.136.103"),
				Length:      108,
			},
		},
		{
			name: "unrecognised protocol keeps the trailing length",
			line: tsText + " (en0, out) IP 10.0.0.1 > 10.0.0.2: GREv0, length 100",
			want: PacketEvent{
				ObservedAt: tsTime,
				Interface:  "en0",
				Direction:  DirectionOut,
				Src:        addrOnly("10.0.0.1"),
				Dst:        addrOnly("10.0.0.2"),
				Length:     100,
			},
		},
		{
			name: "negative length is not a length",
			line: tsText + " (en0, out) IP 10.0.0.1.5 > 10.0.0.2.6: tcp -5",
			want: PacketEvent{
				ObservedAt: tsTime,
				Interface:  "en0",
				Direction:  DirectionOut,
				Protocol:   TCP,
				Src:        ap("10.0.0.1:5"),
				Dst:        ap("10.0.0.2:6"),
				Length:     0,
			},
		},
		{
			name: "no metadata block at all",
			line: tsText + " IP 10.2.0.2.53001 > 1.1.1.1.53: UDP, length 29",
			want: PacketEvent{
				ObservedAt: tsTime,
				Protocol:   UDP,
				Src:        ap("10.2.0.2:53001"),
				Dst:        ap("1.1.1.1:53"),
				Length:     29,
			},
		},
		{
			name: "no direction field",
			line: tsText + " (utun6, proc claude:1084:" + claudeUUID + ") IP 10.2.0.2.63352 > 160.79.104.10.443: tcp 0",
			want: PacketEvent{
				ObservedAt:  tsTime,
				Interface:   "utun6",
				Process:     "claude",
				PID:         1084,
				ProcessUUID: claudeUUID,
				Protocol:    TCP,
				Src:         ap("10.2.0.2:63352"),
				Dst:         ap("160.79.104.10:443"),
			},
		},
		{
			name: "non-numeric PID drops the process, keeps the packet",
			line: tsText + " (utun6, proc claude:abc:" + claudeUUID + ", out) IP 10.2.0.2.63352 > 160.79.104.10.443: tcp 5",
			want: PacketEvent{
				ObservedAt: tsTime,
				Interface:  "utun6",
				Direction:  DirectionOut,
				Protocol:   TCP,
				Src:        ap("10.2.0.2:63352"),
				Dst:        ap("160.79.104.10:443"),
				Length:     5,
			},
		},
		{
			name: "PID above uint32 drops the process, keeps the packet",
			line: tsText + " (utun6, proc claude:4294967296:" + claudeUUID + ", out) IP 10.2.0.2.63352 > 160.79.104.10.443: tcp 5",
			want: PacketEvent{
				ObservedAt: tsTime,
				Interface:  "utun6",
				Direction:  DirectionOut,
				Protocol:   TCP,
				Src:        ap("10.2.0.2:63352"),
				Dst:        ap("160.79.104.10:443"),
				Length:     5,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseTcpdumpLine(tt.line)
			if !ok {
				t.Fatalf("expected a packet event, got ok=false for %q", tt.line)
			}
			assertPacketEvent(t, tt.want, got)
		})
	}
}

func TestParseTcpdumpLineRejectsNonPackets(t *testing.T) {
	lines := map[string]string{
		"empty":                    "",
		"whitespace":               "   \t",
		"listening banner":         "listening on pktap,all, link-type PKTAP (Apple DLT_PKTAP), snapshot length 524288 bytes",
		"tcpdump prefix":           "tcpdump: data link type PKTAP",
		"verbose hint":             "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode",
		"read banner":              "reading from file t.pcap, link-type RAW (Raw IP)",
		"captured stats":           "40 packets captured",
		"filter stats":             "54 packets received by filter",
		"dropped stats":            "0 packets dropped by kernel",
		"ARP":                      tsText + " (en0, svc BE, in) ARP, Request who-has 192.168.178.1 tell 192.168.178.167, length 28",
		"HH:MM:SS timestamp":       "22:04:15.717249 (proc ch.protonvpn.mac:74422, in) IP 192.0.2.1.443 > 198.51.100.10.51690: UDP, length 448",
		"timestamp only":           tsText,
		"truncated block":          tsText + " (utun6, proc claude:10",
		"block without packet":     tsText + " (utun6, proc claude:1084:" + claudeUUID + ", out)",
		"unclosed block":           tsText + " (utun6, proc claude:1084, out IP 10.2.0.2.1 > 1.1.1.1.53: UDP, length 1",
		"bad timestamp":            "abc (utun6, out) IP 10.2.0.2.1 > 1.1.1.1.53: UDP, length 1",
		"missing arrow":            tsText + " (utun6, out) IP 10.2.0.2.63352 160.79.104.10.443: tcp 0",
		"missing colon after dst":  tsText + " (utun6, out) IP 10.2.0.2.63352 > 160.79.104.10.443 tcp 0",
		"invalid source address":   tsText + " (utun6, out) IP 999.1.1.1.5 > 1.1.1.1.53: UDP, length 1",
		"invalid destination":      tsText + " (utun6, out) IP 10.0.0.1.5 > nothost.53: UDP, length 1",
		"port above 65535":         tsText + " (utun6, out) IP 10.0.0.1.99999 > 1.1.1.1.53: UDP, length 1",
		"IP keyword with no addrs": tsText + " (utun6, out) IP",
	}

	for name, line := range lines {
		t.Run(name, func(t *testing.T) {
			if got, ok := parseTcpdumpLine(line); ok {
				t.Fatalf("expected ok=false for %q, got %+v", line, got)
			}
		})
	}
}

func FuzzParseTcpdumpLine(f *testing.F) {
	seeds := []string{
		"",
		tsText + " (utun6, proc claude:1084:" + claudeUUID + ", out) IP 10.2.0.2.63352 > 160.79.104.10.443: tcp 0",
		tsText + " (proc ch.protonvpn.mac:74422, in) IP 192.0.2.1.443 > 198.51.100.10.51690: UDP, length 448",
		tsText + " (en0, svc BE, in) IP6 fe80::1 > ff02::1: ICMP6, router advertisement, length 136",
		tsText + " (utun6, proc Discord Helper (Renderer):1:" + discordUUID + ", out) IP 10.0.0.1 > 10.0.0.2: ESP(spi=0x1,seq=0x1), length 1",
		tsText + " (utun6, proc ::::, out) IP . > .: tcp",
		tsText + " ((((",
		"(" + strings.Repeat("proc a:1, ", 50) + ") IP",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		got, ok := parseTcpdumpLine(line)
		if !ok {
			return
		}
		if got.ObservedAt.IsZero() {
			t.Errorf("ok event without a timestamp: %q", line)
		}
		if !got.Src.Addr().IsValid() || !got.Dst.Addr().IsValid() {
			t.Errorf("ok event without valid addresses: %q -> %+v", line, got)
		}
		if got.Direction != "" && got.Direction != DirectionIn && got.Direction != DirectionOut {
			t.Errorf("unexpected direction %q from %q", got.Direction, line)
		}
		if got.Length < 0 {
			t.Errorf("negative length %d from %q", got.Length, line)
		}
	})
}

func assertPacketEvent(t *testing.T, exp, act PacketEvent) {
	t.Helper()

	if !act.ObservedAt.Equal(exp.ObservedAt) {
		t.Errorf("ObservedAt mismatch: expected %v, got %v", exp.ObservedAt, act.ObservedAt)
	}
	if act.ObservedAt.Location() != time.UTC {
		t.Errorf("ObservedAt must be UTC, got %v", act.ObservedAt.Location())
	}
	if act.Interface != exp.Interface {
		t.Errorf("Interface mismatch: expected %q, got %q", exp.Interface, act.Interface)
	}
	if act.Process != exp.Process {
		t.Errorf("Process mismatch: expected %q, got %q", exp.Process, act.Process)
	}
	if act.PID != exp.PID {
		t.Errorf("PID mismatch: expected %d, got %d", exp.PID, act.PID)
	}
	if act.ProcessUUID != exp.ProcessUUID {
		t.Errorf("ProcessUUID mismatch: expected %q, got %q", exp.ProcessUUID, act.ProcessUUID)
	}
	if act.Direction != exp.Direction {
		t.Errorf("Direction mismatch: expected %q, got %q", exp.Direction, act.Direction)
	}
	if act.Protocol != exp.Protocol {
		t.Errorf("Protocol mismatch: expected %q, got %q", exp.Protocol, act.Protocol)
	}
	if act.Src != exp.Src {
		t.Errorf("Src mismatch: expected %s, got %s", exp.Src, act.Src)
	}
	if act.Dst != exp.Dst {
		t.Errorf("Dst mismatch: expected %s, got %s", exp.Dst, act.Dst)
	}
	if act.Length != exp.Length {
		t.Errorf("Length mismatch: expected %d, got %d", exp.Length, act.Length)
	}
}
