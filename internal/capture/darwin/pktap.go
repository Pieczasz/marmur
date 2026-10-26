//go:build darwin

package darwin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"

	"github.com/Pieczasz/marmur/internal/capture"
)

const (
	pktapDevice  = "pktap,all"
	pktapSnapLen = 512
	pktapTimeout = 100 * time.Millisecond
)

type pktapConfig struct {
	device    string
	snapLen   int
	timeout   time.Duration
	promisc   bool
	immediate bool
	wantPktap bool
}

func defaultPktapConfig() pktapConfig {
	return pktapConfig{
		device:    pktapDevice,
		snapLen:   pktapSnapLen,
		promisc:   false,
		timeout:   pktapTimeout,
		immediate: true,
		wantPktap: true,
	}
}

type packetSource interface {
	ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	Stats() (*pcap.Stats, error)
	Close()
}

// PktapSensor is the darwin PacketSensor adapter.
type PktapSensor struct{}

var _ capture.PacketSensor = PktapSensor{}

func (PktapSensor) Collect(ctx context.Context, emit func(capture.PacketEvent)) (capture.PacketSummary, error) {
	open := func() (packetSource, error) {
		return openPktap(defaultPktapConfig())
	}
	return collectPacketsFrom(ctx, open, emit)
}

func openPktap(cfg pktapConfig) (packetSource, error) {
	inactive, err := setupPCAPInactive(cfg)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()

	handle, err := inactive.Activate()
	if err != nil {
		return nil, fmt.Errorf("pktap: activate: %w", err)
	}

	if err := validateLinkType(handle.LinkType()); err != nil {
		handle.Close()
		return nil, err
	}

	return handle, nil
}

func setupPCAPInactive(cfg pktapConfig) (*pcap.InactiveHandle, error) {
	inactive, err := pcap.NewInactiveHandle(cfg.device)
	if err != nil {
		return nil, fmt.Errorf("pktap: new inactive handle: %w", err)
	}
	if err := inactive.SetSnapLen(cfg.snapLen); err != nil {
		return nil, fmt.Errorf("pktap: set snaplen: %w", err)
	}
	if err := inactive.SetPromisc(cfg.promisc); err != nil {
		return nil, fmt.Errorf("pktap: set promisc: %w", err)
	}
	if err := inactive.SetTimeout(cfg.timeout); err != nil {
		return nil, fmt.Errorf("pktap: set timeout: %w", err)
	}
	if err := inactive.SetImmediateMode(cfg.immediate); err != nil {
		return nil, fmt.Errorf("pktap: set immediate mode: %w", err)
	}
	if err := inactive.SetWantPktap(cfg.wantPktap); err != nil {
		return nil, fmt.Errorf("pktap: set want pktap: %w", err)
	}
	return inactive, nil
}

func validateLinkType(linkType layers.LinkType) error {
	if linkType != layers.LinkTypeApplePKTAP {
		return fmt.Errorf("pktap: link type %d, want ApplePKTAP (%d)", linkType, layers.LinkTypeApplePKTAP)
	}
	return nil
}

func collectPacketsFrom(ctx context.Context, open func() (packetSource, error), emit func(capture.PacketEvent)) (capture.PacketSummary, error) {
	src, err := open()
	if err != nil {
		return capture.PacketSummary{}, err
	}
	defer src.Close()

	var summary capture.PacketSummary
	for ctx.Err() == nil {
		data, ci, err := src.ZeroCopyReadPacketData()
		if err != nil {
			if errors.Is(err, pcap.NextErrorTimeoutExpired) {
				continue
			}
			if ctx.Err() != nil {
				break
			}
			return summary, err
		}

		ev, err := decodePktap(data, ci.Timestamp)
		if err != nil {
			switch {
			case errors.Is(err, errNotIP):
				summary.NonIP++
			case errors.Is(err, errTruncated):
				summary.Truncated++
			case errors.Is(err, errUnsupportedHeader):
				summary.Unsupported++
			default:
				summary.OtherErrors++
			}
			continue
		}

		emit(ev)
		summary.Emitted++
	}

	stats, err := src.Stats()
	if err != nil {
		return summary, err
	}
	if stats != nil {
		summary.PacketsDropped = stats.PacketsDropped
		summary.PacketsIfDropped = stats.PacketsIfDropped
	}
	return summary, nil
}
