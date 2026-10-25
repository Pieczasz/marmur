package tcpdump

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Pieczasz/marmur/internal/capture"
)

// parseTcpdumpLine parses one stdout line of `tcpdump -i pktap,all -n -q -tt -l -k INPDU`.
// It returns false (not ok) for anything that is not an IPv4/IPv6 packet line.
func parseTcpdumpLine(line string) (capture.PacketEvent, bool) {
	timestampString, rest, ok := strings.Cut(line, " ")
	if !ok {
		return capture.PacketEvent{}, false
	}

	timestamp, ok := parseTimestamp(timestampString)
	if !ok {
		return capture.PacketEvent{}, false
	}

	ev := capture.PacketEvent{ObservedAt: timestamp}

	if strings.HasPrefix(rest, "(") {
		end := strings.Index(rest, ") IP")
		if end < 0 {
			return capture.PacketEvent{}, false
		}

		block := rest[1:end]
		rest = rest[end+2:]
		parseMetadata(&ev, block)
	}

	if r, ok := strings.CutPrefix(rest, "IP6 "); ok {
		rest = r
	} else if r, ok := strings.CutPrefix(rest, "IP "); ok {
		rest = r
	} else {
		return capture.PacketEvent{}, false
	}

	src, after, ok := strings.Cut(rest, " > ")
	if !ok {
		return capture.PacketEvent{}, false
	}
	dst, tail, ok := strings.Cut(after, ": ")
	if !ok {
		return capture.PacketEvent{}, false
	}

	if ev.Src, ok = parseHostPort(src); !ok {
		return capture.PacketEvent{}, false
	}
	if ev.Dst, ok = parseHostPort(dst); !ok {
		return capture.PacketEvent{}, false
	}

	parseTail(&ev, tail)

	return ev, true
}

func parseTimestamp(s string) (time.Time, bool) {
	secs, frac, ok := strings.Cut(s, ".")
	if !ok {
		return time.Time{}, false
	}

	sec, err := strconv.ParseInt(secs, 10, 64)
	if err != nil {
		return time.Time{}, false
	}

	usec, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return time.Time{}, false
	}

	return time.Unix(sec, usec*1000).UTC(), true
}

func parseMetadata(ev *capture.PacketEvent, block string) {
	for i, field := range strings.Split(block, ", ") {
		switch {
		case field == "in" || field == "out":
			ev.Direction = capture.Direction(field)
		case strings.HasPrefix(field, "proc "):
			parseProc(ev, strings.TrimPrefix(field, "proc "))
		case i == 0 && !strings.Contains(field, " "):
			ev.Interface = field
		}
	}
}

func parseProc(ev *capture.PacketEvent, val string) {
	parts := strings.Split(val, ":")
	var uuid string

	if last := parts[len(parts)-1]; len(parts) >= 3 && isUUID(last) {
		uuid = last
		parts = parts[:len(parts)-1]
	}

	pid, err := strconv.ParseUint(parts[len(parts)-1], 10, 32)
	if err != nil {
		return
	}
	ev.PID = uint32(pid)
	ev.Process = strings.Join(parts[:len(parts)-1], ":")
	ev.ProcessUUID = uuid
}

func isUUID(s string) bool {
	return len(s) == 36 && strings.Count(s, "-") == 4
}

func parseHostPort(s string) (netip.AddrPort, bool) {
	if addr, err := netip.ParseAddr(s); err == nil {
		return netip.AddrPortFrom(addr, 0), true
	}

	i := strings.LastIndex(s, ".")
	if i < 0 {
		return netip.AddrPort{}, false
	}

	addr, err := netip.ParseAddr(s[:i])
	if err != nil {
		return netip.AddrPort{}, false
	}

	port, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil {
		return netip.AddrPort{}, false
	}

	return netip.AddrPortFrom(addr, uint16(port)), true
}

func parseTail(ev *capture.PacketEvent, tail string) {
	if n, ok := strings.CutPrefix(tail, "tcp "); ok {
		ev.Protocol = capture.TCP
		ev.Length = parseLength(n)
		return
	}

	switch {
	case strings.HasPrefix(tail, "UDP,"):
		ev.Protocol = capture.UDP
	case strings.HasPrefix(tail, "ICMP6"):
		ev.Protocol = capture.ICMPv6
	case strings.HasPrefix(tail, "ICMP"):
		ev.Protocol = capture.ICMP
	case strings.HasPrefix(tail, "ESP("):
		ev.Protocol = capture.ESP
	}

	if i := strings.LastIndex(tail, "length "); i >= 0 {
		ev.Length = parseLength(tail[i+len("length "):])
	}
}

func parseLength(s string) int {
	n, err := strconv.ParseUint(s, 10, 31)
	if err != nil {
		return 0
	}
	return int(n)
}
