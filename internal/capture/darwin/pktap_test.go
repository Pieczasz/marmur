//go:build darwin

package darwin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/stretchr/testify/require"

	"github.com/Pieczasz/marmur/internal/capture"
)

type fakeRead struct {
	data []byte
	ci   gopacket.CaptureInfo
	err  error
}

type fakeSource struct {
	statsErr error
	stats    *pcap.Stats
	onRead   func(int)
	steps    []fakeRead
	buf      []byte
	index    int
	reuse    bool
	closed   bool
}

func TestDefaultPktapConfig(t *testing.T) {
	t.Parallel()

	want := pktapConfig{
		device:    "pktap,all",
		snapLen:   512,
		promisc:   false,
		timeout:   100 * time.Millisecond,
		immediate: true,
		wantPktap: true,
	}
	require.Equal(t, want, defaultPktapConfig())
}

func TestValidateLinkType(t *testing.T) {
	t.Parallel()

	require.NoError(t, validateLinkType(layers.LinkTypeApplePKTAP))
	require.Error(t, validateLinkType(layers.LinkTypeEthernet))
}

func (f *fakeSource) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	if f.index >= len(f.steps) {
		if f.onRead != nil {
			f.onRead(f.index)
		}
		return nil, gopacket.CaptureInfo{}, pcap.NextErrorTimeoutExpired
	}

	step := f.steps[f.index]
	f.index++

	data := step.data
	if step.err == nil && f.reuse {
		if cap(f.buf) < len(data) {
			f.buf = make([]byte, len(data))
		}
		f.buf = f.buf[:len(data)]
		copy(f.buf, data)
		data = f.buf
	}

	if f.onRead != nil {
		f.onRead(f.index)
	}
	if step.err != nil {
		return nil, gopacket.CaptureInfo{}, step.err
	}
	return data, step.ci, nil
}

func (f *fakeSource) Stats() (*pcap.Stats, error) {
	if f.statsErr != nil {
		return nil, f.statsErr
	}
	if f.stats != nil {
		return f.stats, nil
	}
	return &pcap.Stats{}, nil
}

func TestCollectPacketsFromCountsAndEmits(t *testing.T) {
	t.Parallel()

	validData := fxRecord{dlt: 1, ifname: "en0", flags: fxFlagOut, pre: 14, pid: 1084, comm: "claude", uuid: fxUUID}.
		build(fxEthernet, fxIPv4("10.2.0.2", "160.79.104.10", 6, fxTCP(63352, 443, 20), 20+20+7))
	wantEvent := capture.PacketEvent{
		ObservedAt: fxTS.UTC(), Interface: "en0", Direction: capture.DirectionOut,
		Process: "claude", PID: 1084, ProcessUUID: fxUUIDText,
		Protocol: capture.TCP, Src: ap("10.2.0.2:63352"), Dst: ap("160.79.104.10:443"), Length: 7,
	}

	validIP := fxIPv4("10.0.0.1", "10.0.0.2", 17, fxUDP(1, 2, 0), 28)
	tests := []struct {
		name string
		step fakeRead
	}{
		{
			name: "non-IP",
			step: pktRead(fxRecord{dlt: 1, pre: 14}.
				build(fxEthernet, []byte{0x00, 0x01, 0x08, 0x00, 6, 4, 0, 1})),
		},
		{
			name: "truncated",
			step: pktRead(fxRecord{dlt: 1, pre: 14}.build(fxEthernet, validIP[:10])),
		},
		{
			name: "unsupported header",
			step: pktRead(fxRecord{hdrLen: 100}.build(nil, nil)),
		},
	}

	steps := []fakeRead{pktRead(validData)}
	for _, tt := range tests {
		steps = append(steps, tt.step)
	}
	steps = append(steps, fakeRead{err: pcap.NextErrorTimeoutExpired})

	stats := &pcap.Stats{PacketsDropped: 7, PacketsIfDropped: 2}
	src := &fakeSource{steps: steps, stats: stats}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src.onRead = func(n int) {
		if n == len(steps) {
			cancel()
		}
	}

	var events []capture.PacketEvent
	summary, err := collectPacketsFrom(ctx, openSource(src, nil), func(ev capture.PacketEvent) {
		events = append(events, ev)
	})
	if err != nil {
		t.Fatalf("collectPacketsFrom: %v", err)
	}

	want := capture.PacketSummary{
		Emitted:          1,
		NonIP:            1,
		Truncated:        1,
		Unsupported:      1,
		PacketsDropped:   7,
		PacketsIfDropped: 2,
	}
	require.Equal(t, want, summary)
	require.Len(t, events, 1)
	require.Equal(t, wantEvent, events[0])
	require.True(t, src.closed)
}

func TestCollectPacketsFromIgnoresTimeouts(t *testing.T) {
	t.Parallel()

	validData := fxRecord{dlt: 1, ifname: "en0", flags: fxFlagIn, pre: 14, pid: 1, comm: "a"}.
		build(fxEthernet, fxIPv4("10.0.0.1", "10.0.0.2", 17, fxUDP(1, 2, 3), 31))

	steps := []fakeRead{
		{err: pcap.NextErrorTimeoutExpired},
		pktRead(validData),
		{err: pcap.NextErrorTimeoutExpired},
	}
	src := &fakeSource{steps: steps}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src.onRead = func(n int) {
		if n == len(steps) {
			cancel()
		}
	}

	var emitted int
	summary, err := collectPacketsFrom(ctx, openSource(src, nil), func(capture.PacketEvent) {
		emitted++
	})
	require.NoError(t, err)
	require.Equal(t, 1, summary.Emitted)
	require.Equal(t, 1, emitted)
	require.Equal(t, capture.PacketSummary{Emitted: 1}, summary)
}

func TestCollectPacketsFromFatalReadError(t *testing.T) {
	t.Parallel()

	validData := fxRecord{dlt: 1, ifname: "en0", flags: fxFlagOut, pre: 14, pid: 1, comm: "a"}.
		build(fxEthernet, fxIPv4("10.0.0.1", "10.0.0.2", 17, fxUDP(1, 2, 3), 31))
	errRead := errors.New("pcap read failed")

	src := &fakeSource{steps: []fakeRead{
		pktRead(validData),
		{err: errRead},
	}}

	var emitted int
	summary, err := collectPacketsFrom(context.Background(), openSource(src, nil), func(capture.PacketEvent) {
		emitted++
	})
	require.ErrorIs(t, err, errRead)
	require.Equal(t, 1, summary.Emitted)
	require.Equal(t, 1, emitted)
	require.True(t, src.closed)
}

func TestCollectPacketsFromStatsError(t *testing.T) {
	t.Parallel()

	validData := fxRecord{dlt: 1, ifname: "en0", flags: fxFlagOut, pre: 14, pid: 1, comm: "a"}.
		build(fxEthernet, fxIPv4("10.0.0.1", "10.0.0.2", 17, fxUDP(1, 2, 3), 31))
	errStats := errors.New("stats failed")

	steps := []fakeRead{pktRead(validData)}
	src := &fakeSource{steps: steps, statsErr: errStats}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src.onRead = func(n int) {
		if n == len(steps) {
			cancel()
		}
	}

	summary, err := collectPacketsFrom(ctx, openSource(src, nil), func(capture.PacketEvent) {})
	require.ErrorIs(t, err, errStats)
	require.Equal(t, 1, summary.Emitted)
	require.True(t, src.closed)
}

func TestCollectPacketsFromOpenError(t *testing.T) {
	t.Parallel()

	errOpen := errors.New("open failed")

	summary, err := collectPacketsFrom(context.Background(), openSource(nil, errOpen), func(capture.PacketEvent) {
		t.Fatal("emit called after open error")
	})
	require.ErrorIs(t, err, errOpen)
	require.Equal(t, capture.PacketSummary{}, summary)
}

func TestCollectPacketsFromContextCancel(t *testing.T) {
	t.Parallel()

	src := &fakeSource{steps: []fakeRead{{err: pcap.NextErrorTimeoutExpired}}}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src.onRead = func(int) { cancel() }

	summary, err := collectPacketsFrom(ctx, openSource(src, nil), func(capture.PacketEvent) {
		t.Fatal("emit called after cancel")
	})
	require.NoError(t, err)
	require.Equal(t, capture.PacketSummary{}, summary)
	require.True(t, src.closed)
}

func TestCollectPacketsFromDoesNotRetainZeroCopyData(t *testing.T) {
	t.Parallel()

	first := fxRecord{dlt: 1, ifname: "en0", flags: fxFlagOut, pre: 14, pid: 1, comm: "claude"}.
		build(fxEthernet, fxIPv4("10.0.0.1", "10.0.0.2", 17, fxUDP(1000, 2000, 3), 31))
	second := fxRecord{dlt: 1, ifname: "en0", flags: fxFlagIn, pre: 14, pid: 2, comm: "zen"}.
		build(fxEthernet, fxIPv4("10.0.0.3", "10.0.0.4", 17, fxUDP(3000, 4000, 3), 31))

	steps := []fakeRead{pktRead(first), pktRead(second)}
	src := &fakeSource{steps: steps, reuse: true}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src.onRead = func(n int) {
		if n == len(steps) {
			cancel()
		}
	}

	var events []capture.PacketEvent
	if _, err := collectPacketsFrom(ctx, openSource(src, nil), func(ev capture.PacketEvent) {
		events = append(events, ev)
	}); err != nil {
		t.Fatalf("collectPacketsFrom: %v", err)
	}

	require.Len(t, events, 2)
	require.Equal(t, "claude", events[0].Process)
	require.Equal(t, uint32(1), events[0].PID)
	require.Equal(t, ap("10.0.0.1:1000"), events[0].Src)
	require.Equal(t, "zen", events[1].Process)
	require.Equal(t, uint32(2), events[1].PID)
	require.Equal(t, ap("10.0.0.3:3000"), events[1].Src)
}

func (f *fakeSource) Close() {
	f.closed = true
}

func openSource(src packetSource, err error) func() (packetSource, error) {
	return func() (packetSource, error) { return src, err }
}

func pktRead(data []byte) fakeRead {
	return fakeRead{
		data: data,
		ci:   gopacket.CaptureInfo{Timestamp: fxTS},
	}
}
