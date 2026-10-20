package collector

import (
	"bufio"
	"io"
)

const maxLineBytes = 1 << 20

func readPackets(r io.Reader, emit func(PacketEvent)) (skipped int, err error) {
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
