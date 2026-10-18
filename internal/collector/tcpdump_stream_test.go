package collector

import (
	"errors"
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

const (
	streamOut = tsText + " (utun6, proc claude:98087:" + claudeUUID + ", out) IP 10.2.0.2.63154 > 160.79.104.10.443: tcp 0"
	streamIn  = tsText + " (utun6, proc claude:98087:" + claudeUUID + ", eproc claude:98087:, in) IP 160.79.104.10.443 > 10.2.0.2.63178: tcp 279"
	streamUDP = tsText + " (en0, proc ch.protonvpn.mac:65632:" + protonUUID + ", out) IP 192.168.178.167.62125 > 62.169.136.103.500: UDP, length 80"
)

func collect(t *testing.T, r io.Reader) ([]PacketEvent, int, error) {
	t.Helper()
	var got []PacketEvent
	skipped, err := readPackets(r, func(ev PacketEvent) { got = append(got, ev) })
	return got, skipped, err
}

func TestReadPacketsMixedOutput(t *testing.T) {
	input := strings.Join([]string{
		"tcpdump: data link type PKTAP",
		"listening on pktap,all, link-type PKTAP (Apple DLT_PKTAP), snapshot length 524288 bytes",
		streamOut,
		"",
		streamIn,
		"garbage",
		streamUDP,
		"20 packets captured",
	}, "\n") + "\n"

	got, skipped, err := collect(t, strings.NewReader(input))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if skipped != 5 {
		t.Errorf("skipped: expected 5, got %d", skipped)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 events, got %d", len(got))
	}

	wantLengths := []int{0, 279, 80}
	wantDirs := []Direction{DirectionOut, DirectionIn, DirectionOut}
	wantProtos := []Protocol{TCP, TCP, UDP}
	for i, ev := range got {
		if ev.Length != wantLengths[i] || ev.Direction != wantDirs[i] || ev.Protocol != wantProtos[i] {
			t.Errorf("[%d] events out of order or wrong: got %+v", i, ev)
		}
	}
}

func TestReadPacketsEmptyInput(t *testing.T) {
	got, skipped, err := collect(t, strings.NewReader(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 || skipped != 0 {
		t.Errorf("expected nothing, got %d events, %d skipped", len(got), skipped)
	}
}

func TestReadPacketsLastLineWithoutNewline(t *testing.T) {
	got, skipped, err := collect(t, strings.NewReader(streamOut+"\n"+streamIn))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 2 || skipped != 0 {
		t.Fatalf("expected 2 events and 0 skipped, got %d events, %d skipped", len(got), skipped)
	}
	if got[1].Length != 279 {
		t.Errorf("last line parsed wrong: %+v", got[1])
	}
}

func TestReadPacketsLongLineDoesNotStopReading(t *testing.T) {
	long := strings.Repeat("x", 100*1024)
	input := streamOut + "\n" + long + "\n" + streamUDP + "\n"

	got, skipped, err := collect(t, strings.NewReader(input))
	if err != nil {
		t.Fatalf("a long line must not be an error, got: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 events (before and after the long line), got %d", len(got))
	}
	if skipped != 1 {
		t.Errorf("skipped: expected 1, got %d", skipped)
	}
	if got[1].Protocol != UDP {
		t.Errorf("event after the long line parsed wrong: %+v", got[1])
	}
}

func TestReadPacketsReturnsReaderError(t *testing.T) {
	boom := errors.New("pipe broke")
	r := io.MultiReader(
		strings.NewReader(streamOut+"\n"+streamIn+"\n"),
		iotest.ErrReader(boom),
	)

	got, _, err := collect(t, r)
	if !errors.Is(err, boom) {
		t.Fatalf("expected the reader error, got: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("events before the error must still be emitted: expected 2, got %d", len(got))
	}
}
