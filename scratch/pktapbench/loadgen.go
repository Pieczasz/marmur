package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// generate sends pps 64-byte UDP datagrams per second to a receiver on 127.0.0.1:port until ctx ends.
// Loopback only: nothing leaves the machine. PKTAP sees each datagram twice (lo0 out and lo0 in).
func generate(ctx context.Context, pps, port int) (sent int, err error) {
	recv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		return 0, err
	}
	defer recv.Close()
	_ = recv.SetReadBuffer(8 << 20)
	go func() { // drain, so no ICMP port-unreachable traffic is generated
		buf := make([]byte, 2048)
		for {
			if _, _, err := recv.ReadFromUDP(buf); err != nil {
				return
			}
		}
	}()

	conn, err := net.DialUDP("udp4", nil, recv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	payload := make([]byte, 64)
	start := time.Now()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return sent, nil
		case <-tick.C:
		}
		due := int(time.Since(start).Seconds() * float64(pps))
		for sent < due {
			if _, err := conn.Write(payload); err != nil {
				if errors.Is(err, syscall.ENOBUFS) {
					break // socket buffer full: try again next tick
				}
				return sent, err
			}
			sent++
		}
	}
}

// runLoadgen is the child-process entry point: -mode loadgen.
func runLoadgen(pps int, d time.Duration, port int) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	sent, err := generate(ctx, pps, port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "loadgen:", err)
		os.Exit(1)
	}
	fmt.Printf("sent %d\n", sent)
}

// startLoadgen runs the load generator as a separate process, as the invoking (non-root) user,
// so its CPU time is never counted against the collector being measured.
// The returned wait function blocks until it exits and returns how many datagrams it sent.
func startLoadgen(pps int, d time.Duration, port int) (wait func() (int, error), err error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "-mode", "loadgen", "-pps", strconv.Itoa(pps), "-d", d.String(), "-port", strconv.Itoa(port))
	if uid, gid := os.Getenv("SUDO_UID"), os.Getenv("SUDO_GID"); uid != "" && gid != "" {
		u, _ := strconv.Atoi(uid)
		g, _ := strconv.Atoi(gid)
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(u), Gid: uint32(g)}}
	}
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return func() (int, error) {
		sent := -1
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if n, ok := strings.CutPrefix(sc.Text(), "sent "); ok {
				sent, _ = strconv.Atoi(n)
			}
		}
		if err := cmd.Wait(); err != nil {
			return sent, err
		}
		return sent, nil
	}, nil
}
