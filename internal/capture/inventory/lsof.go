package inventory

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

	"github.com/Pieczasz/marmur/internal/capture"
)

// LsofSensor implements capture.SocketSensor with lsof.
type LsofSensor struct{}

var _ capture.SocketSensor = LsofSensor{}

func (LsofSensor) Collect(ctx context.Context, emit func(capture.SocketEvent)) (capture.SocketSummary, error) {
	n, err := collectSockets(ctx, emit)
	if err != nil {
		return capture.SocketSummary{}, err
	}
	return capture.SocketSummary{Emitted: n}, nil
}

func collectSockets(ctx context.Context, emit func(capture.SocketEvent)) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "lsof", "-i", "-n", "-P", "-F", "pcufPTn")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return 0, fmt.Errorf("lsof: stdout pipe: %w", err)
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("lsof: start: %w", err)
	}

	parser := newLSOFParser(time.Now().UTC())
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		currentLine := scanner.Text()
		if len(currentLine) < 2 {
			continue
		}

		flag := currentLine[0]
		val := currentLine[1:]
		parser.parseFlag(flag, val)
	}
	readErr := scanner.Err()
	if readErr != nil {
		_ = cmd.Process.Kill()
	}

	waitErr := cmd.Wait()
	switch {
	case readErr != nil:
		return 0, fmt.Errorf("lsof: read: %w", readErr)
	case ctx.Err() != nil:
		return 0, ctx.Err()
	case waitErr != nil:
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return 0, fmt.Errorf("lsof: %w: %s", waitErr, msg)
		}
		return 0, fmt.Errorf("lsof: %w", waitErr)
	}

	events := parser.finish()
	for _, ev := range events {
		emit(ev)
	}
	return len(events), nil
}

type lsofParser struct {
	now time.Time

	currentCmd   string
	currentUser  string
	currentEvent *capture.SocketEvent
	events       []capture.SocketEvent

	currentPID uint32
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
	ev := &capture.SocketEvent{
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
		ev.AccessMode = string(last)
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

	protocol := capture.Protocol(strings.ToUpper(val))
	switch protocol {
	case capture.TCP, capture.UDP, capture.ICMP, capture.ICMPv6:
		p.currentEvent.Protocol = protocol
	}
}

func (p *lsofParser) parseState(val string) {
	if p.currentEvent == nil {
		return
	}

	state, ok := strings.CutPrefix(val, "ST=")
	if !ok {
		return
	}
	p.currentEvent.TCPState = capture.TCPState(state)
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

func parseEndpoint(raw string) capture.SocketEndpoint {
	var ep capture.SocketEndpoint

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
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return ep
	}
	ep.Port = uint16(n)
	return ep
}

func (p *lsofParser) finish() []capture.SocketEvent {
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
