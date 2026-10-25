package tcpdump

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/Pieczasz/marmur/internal/capture"
)

const maxLineBytes = 1 << 20

// Sensor implements capture.PacketSensor by running tcpdump and parsing its
// stdout. Args are OS-specific; the caller decides whether to use pktap, any,
// -k, and so on.
type Sensor struct {
	Path string
	Args []string
}

var _ capture.PacketSensor = Sensor{}

func (s Sensor) Collect(ctx context.Context, emit func(capture.PacketEvent)) (capture.PacketSummary, error) {
	path := s.Path
	if path == "" {
		path = "tcpdump"
	}

	cmd := exec.CommandContext(ctx, path, s.Args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return capture.PacketSummary{}, err
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return capture.PacketSummary{}, err
	}

	emitted := 0
	_, readErr := readPackets(stdout, func(ev capture.PacketEvent) {
		emit(ev)
		emitted++
	})
	if readErr != nil {
		_ = cmd.Process.Kill()
	}

	waitErr := cmd.Wait()
	summary := capture.PacketSummary{Emitted: emitted}

	switch {
	case readErr != nil:
		return summary, readErr
	case ctx.Err() != nil:
		return summary, nil
	case waitErr != nil:
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return summary, fmt.Errorf("tcpdump: %w: %s", waitErr, msg)
		}
		return summary, fmt.Errorf("tcpdump: %w", waitErr)
	default:
		return summary, nil
	}
}

func readPackets(r io.Reader, emit func(capture.PacketEvent)) (skipped int, err error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), maxLineBytes)

	for scanner.Scan() {
		ev, ok := parseTcpdumpLine(scanner.Text())
		if !ok {
			skipped++
			continue
		}
		emit(ev)
	}
	return skipped, scanner.Err()
}
