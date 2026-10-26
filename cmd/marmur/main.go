//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/Pieczasz/marmur/internal/capture"
	"github.com/Pieczasz/marmur/internal/capture/darwin"
	"github.com/Pieczasz/marmur/internal/capture/inventory"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		usage(stderr)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch args[0] {
	case "capture":
		err = runCapture(ctx, stdout, stderr)
	case "snapshot":
		err = runSnapshot(ctx, stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "marmur: unknown subcommand %q\n", args[0])
		usage(stderr)
		return 2
	}

	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

func usage(stderr io.Writer) {
	_, _ = fmt.Fprint(stderr, `usage: marmur <command>

commands:
	capture		one JSON packet per line until Ctrl-C (needs root permissions)
	snapshot	one JSON socket per line (lsof)
`)
}

func runCapture(ctx context.Context, stdout, stderr io.Writer) error {
	enc := json.NewEncoder(stdout)
	sensor := darwin.PktapSensor{}

	summary, err := sensor.Collect(ctx, func(ev capture.PacketEvent) {
		_ = enc.Encode(ev)
	})
	if err != nil {
		return err
	}

	return json.NewEncoder(stderr).Encode(summary)
}

func runSnapshot(ctx context.Context, stdout, stderr io.Writer) error {
	enc := json.NewEncoder(stdout)
	sensor := inventory.LsofSensor{}

	summary, err := sensor.Collect(ctx, func(ev capture.SocketEvent) {
		_ = enc.Encode(ev)
	})
	if err != nil {
		return err
	}

	_, _ = fmt.Fprintf(stderr, "snapshot: %d sockets\n", summary.Emitted)
	return nil
}
