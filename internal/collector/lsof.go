package collector

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Protocol string

const (
	TCP    Protocol = "TCP"
	UDP    Protocol = "UDP"
	ICMP   Protocol = "ICMP"
	ICMPv6 Protocol = "ICMPV6"
	ESP    Protocol = "ESP"
)

type TCPState string

const (
	StateEstablished TCPState = "ESTABLISHED"
	StateListen      TCPState = "LISTEN"
	StateCloseWait   TCPState = "CLOSE_WAIT"
	StateTimeWait    TCPState = "TIME_WAIT"
	StateSynSent     TCPState = "SYN_SENT"
	StateNone        TCPState = "" // For UDP / ICMP
)

type SocketEndpoint struct {
	Addr       netip.Addr
	Port       uint16
	IsWildcard bool
}

type SocketEvent struct {
	ObservedAt time.Time `json:"observed_at"`

	Command string `json:"command"`
	PID     uint32 `json:"pid"`
	User    string `json:"user"`

	FileDescriptor uint32 `json:"file_descriptor"`
	AccessMode     rune   `json:"access_mode"`

	Protocol Protocol `json:"protocol"`
	TCPState TCPState `json:"tcp_state"`

	// For now, we don't need that, it's a hexadecimal kernel address that could be correlated with
	// raw kernel dumps or XNU source debugging.
	// Device string `json:"device,omitempty"`

	Local  SocketEndpoint  `json:"local"`
	Remote *SocketEndpoint `json:"remote,omitempty"`
}

func (e *SocketEvent) IsIPv4() bool {
	return e.Local.Addr.Is4() || (e.Remote != nil && e.Remote.Addr.Is4())
}

func (e *SocketEvent) IsIPv6() bool {
	return e.Local.Addr.Is6() || (e.Remote != nil && e.Remote.Addr.Is6())
}

// CollectSockets uses lsof to get all socket events running on this machine.
// The lsof command is run with the flags below:
// p (PID), c (command), u (user), f (FD), P (protocol), T (state), n (endpoints)
func CollectSockets(ctx context.Context) ([]SocketEvent, error) {
	cmd := exec.CommandContext(ctx, "lsof", "-i", "-n", "-P", "-F", "pcufPTn")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("lsof exec failed %w", err)
	}

	parser := newLSOFParser(time.Now().UTC())
	scanner := bufio.NewScanner(bytes.NewReader(out))

	for scanner.Scan() {
		currentLine := scanner.Text()
		if len(currentLine) < 2 {
			continue
		}

		flag := currentLine[0]
		val := currentLine[1:]

		parser.parseFlag(flag, val)
	}

	return parser.finish(), nil

}

type lsofParser struct {
	now time.Time

	currentPID   uint32
	currentCmd   string
	currentUser  string
	currentEvent *SocketEvent

	events []SocketEvent
}

func newLSOFParser(now time.Time) *lsofParser {
	return &lsofParser{now: now}
}

func (p *lsofParser) parseFlag(tag byte, val string) {
	switch tag {
	case 'p':
		p.parseProcess(val)
	case 'c':
		p.currentCmd = val
	case 'u':
		p.currentUser = val
	case 'f':
		p.parseFileDescriptor(val)
	case 'P':
		p.parseProtocol(val)
	case 'T':
		p.parseState(val)
	case 'n':
		p.parseEndpoints(val)
	default:
		return
	}
}

func (p *lsofParser) parseProcess(val string) {
	p.flush()
	pid, err := strconv.ParseUint(val, 10, 32)
	if err != nil {
		return
	}
	p.currentPID = uint32(pid)
}

func (p *lsofParser) parseFileDescriptor(val string) {
	p.flush()
	ev := &SocketEvent{
		ObservedAt: p.now,
		Command:    p.currentCmd,
		PID:        p.currentPID,
		User:       p.currentUser,
	}
	p.currentEvent = ev

	if val == "" {
		return
	}

	num := val
	last := val[len(val)-1]
	if last == 'u' || last == 'r' || last == 'w' {
		ev.AccessMode = rune(last)
		num = val[:len(val)-1]
	}
	fd, err := strconv.ParseUint(num, 10, 32)
	if err != nil {
		return
	}

	ev.FileDescriptor = uint32(fd)
}

func (p *lsofParser) parseProtocol(val string) {
	if p.currentEvent == nil {
		return
	}

	p.currentEvent.Protocol = Protocol(strings.ToUpper(val))
}

func (p *lsofParser) parseState(val string) {
	if p.currentEvent == nil {
		return
	}

	state, ok := strings.CutPrefix(val, "ST=")
	if !ok {
		return
	}
	p.currentEvent.TCPState = TCPState(state)
}

func (p *lsofParser) parseEndpoints(val string) {
	if p.currentEvent == nil {
		return
	}

	local, remote, ok := strings.Cut(val, "->")
	p.currentEvent.Local = parseEndpoint(local)
	if !ok {
		return
	}

	r := parseEndpoint(remote)
	p.currentEvent.Remote = &r
}

func parseEndpoint(raw string) SocketEndpoint {
	var ep SocketEndpoint

	colon := strings.LastIndex(raw, ":")
	if colon < 0 {
		ep.IsWildcard = raw == "*"
		return ep
	}

	host := raw[:colon]
	port := raw[colon+1:]

	if host == "*" {
		ep.IsWildcard = true
	} else if addr, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		ep.Addr = addr
	}

	if port == "*" {
		return ep
	}
	n, err := strconv.ParseUint(port, 10, 32)
	if err != nil {
		return ep
	}
	ep.Port = uint16(n)
	return ep
}

func (p *lsofParser) finish() []SocketEvent {
	p.flush()
	return p.events
}

func (p *lsofParser) flush() {
	if p.currentEvent == nil || p.currentEvent.Protocol == "" {
		p.currentEvent = nil
		return
	}
	p.events = append(p.events, *p.currentEvent)
	p.currentEvent = nil
}
