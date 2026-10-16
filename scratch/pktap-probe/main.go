// Throwaway probe. Not part of the collector.
// Prints PKTAP metadata only: link type, header version, PID, short name, flags, length.
// Snaplen is 128 bytes so the TLS body is never captured.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	flagDirIn  = 0x00000001
	flagDirOut = 0x00000002
	flagV2     = 0x00080000
)

func main() {
	iface := "pktap,en0"
	if len(os.Args) > 1 {
		iface = os.Args[1]
	}

	handle, err := pcap.OpenLive(iface, 128, false, 200*time.Millisecond)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", iface, err)
		os.Exit(1)
	}
	defer handle.Close()

	links, err := handle.ListDataLinks()
	if err != nil {
		fmt.Fprintf(os.Stderr, "list datalinks: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("iface=%s default=%s (%d) snap=%d\n", iface, handle.LinkType(), int(handle.LinkType()), handle.SnapLen())
	for _, link := range links {
		val := pcap.DatalinkNameToVal(link.Name)
		fmt.Printf("available %s (%d) %s\n", link.Name, val, link.Description)
	}
	if val := pcap.DatalinkNameToVal("PKTAP"); val != -1 {
		if err := handle.SetLinkType(layers.LinkType(val)); err != nil {
			fmt.Fprintf(os.Stderr, "set PKTAP (%d): %v\n", val, err)
		}
	}
	fmt.Printf("active=%s (%d)\n", handle.LinkType(), int(handle.LinkType()))

	deadline := time.Now().Add(8 * time.Second)
	seen := 0
	v2 := 0
	other := 0
	for time.Now().Before(deadline) && seen < 20 {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			if err == pcap.NextErrorTimeoutExpired {
				continue
			}
			fmt.Fprintf(os.Stderr, "read: %v\n", err)
			os.Exit(1)
		}
		seen++
		head := data
		if len(head) > 40 {
			head = head[:40]
		}
		pid, comm, flags, ok := parseMeta(data)
		if ok {
			v2++
		} else {
			other++
		}
		fmt.Printf("n=%d cap=%d orig=%d v2=%v pid=%d comm=%q flags=%#x in=%v out=%v head=%x\n",
			seen, ci.CaptureLength, ci.Length, ok, pid, comm, flags,
			flags&flagDirIn != 0, flags&flagDirOut != 0, head)
	}
	fmt.Printf("done seen=%d v2=%d other=%d\n", seen, v2, other)
	if seen == 0 {
		os.Exit(2)
	}
}

// parseMeta reads a v2 PKTAP header. v2 is identified by PTH_FLAG_V2_HDR
// at offset 36, which the xnu header says shares that offset with v1 flags.
// The process name is not at a fixed offset; it lives at pth_comm_offset.
func parseMeta(b []byte) (pid int32, comm string, flags uint32, ok bool) {
	if len(b) < 40 {
		return 0, "", 0, false
	}
	flags = binary.LittleEndian.Uint32(b[36:40])
	if flags&flagV2 == 0 {
		return 0, "", flags, false
	}
	pid = int32(binary.LittleEndian.Uint32(b[28:32]))
	off := int(b[4])
	if off > 0 && off < len(b) {
		end := off
		for end < len(b) && b[end] != 0 && end-off < 17 {
			end++
		}
		comm = string(b[off:end])
	}
	return pid, comm, flags, true
}
