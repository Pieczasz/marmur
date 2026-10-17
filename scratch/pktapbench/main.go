// Throwaway benchmark. Not part of the collector.
//
// Compares two ways of getting per-process packet metadata on macOS:
//
//	tcpdump:  /usr/sbin/tcpdump -i pktap,all -n -q -tt -l -k INPDU, parsed with parseTcpdumpLine
//	gopacket: libpcap in-process with pcap_set_want_pktap, PKTAP header decoded directly
//
// Needs root. Run through run.sh, which builds as you and runs this with sudo.
// No packet payload is printed or stored; only header metadata and counters.
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

const iface = "pktap,all"

var tcpdumpArgs = []string{"-i", iface, "-n", "-q", "-tt", "-l", "-k", "INPDU"}

// pkt is what one tool tells us about one packet.
type pkt struct {
	ts       time.Time
	iface    string
	proc     string
	pid      uint32
	uuid     string
	dir      Direction
	proto    Protocol
	src, dst netip.AddrPort
	length   int

	// gopacket only
	epid      uint32
	ecomm     string
	euuid     string
	flowid    uint32
	flags     uint32
	svc       string
	caplen    int
	hdrLength uint32

	// for diagnosing length disagreements
	ipVer      int
	ipLenField int // IPv4 total length or IPv6 payload length, as in the header
	wireLen    int // bytes after the link header, from the capture's original length
}

// noPID is what PKTAP puts in pth_pid / pth_epid when no process is known (-1 as uint32).
const noPID = 0xFFFFFFFF

func main() {
	mode := flag.String("mode", "matrix", "matrix | compare | loadgen (internal)")
	dur := flag.Duration("d", 10*time.Second, "duration of each run")
	snaplen := flag.Int("snaplen", 512, "snap length requested from libpcap (gopacket)")
	ratesFlag := flag.String("rates", "5000,20000,50000", "load generator rates in datagrams/s (matrix)")
	pps := flag.Int("pps", 5000, "load generator rate (compare, loadgen)")
	port := flag.Int("port", 49999, "loopback UDP port used by the load generator")
	flag.Parse()

	if *mode == "loadgen" {
		runLoadgen(*pps, *dur, *port)
		return
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "needs root: run ./run.sh")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	switch *mode {
	case "matrix":
		var rates []int
		for _, s := range strings.Split(*ratesFlag, ",") {
			r, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil {
				fmt.Fprintln(os.Stderr, "bad -rates:", err)
				os.Exit(2)
			}
			rates = append(rates, r)
		}
		matrix(ctx, rates, *dur, *snaplen, *port)
		fmt.Printf("\n==================== compare at %d datagrams/s (both at once, same traffic) ====================\n", rates[0])
		compareRun(ctx, rates[0], *dur, *snaplen, *port)
	case "compare":
		fmt.Printf("\n==================== compare at %d datagrams/s ====================\n", *pps)
		compareRun(ctx, *pps, *dur, *snaplen, *port)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode")
		os.Exit(2)
	}
}

// ---------------------------------------------------------------- runs

type result struct {
	collector  string
	rate       int
	wall       time.Duration
	packets    int // all packets captured
	loadSeen   int // packets of the load generator captured
	loadSent   int // datagrams the load generator sent (×2 expected: lo0 out + in)
	drops      int // -1 when unknown
	cpu        rusage
	errorsSeen int // decode errors (gopacket) or rejected lines (tcpdump)
	extras     []pkt
}

func isLoad(p pkt, port int) bool {
	return int(p.dst.Port()) == port || int(p.src.Port()) == port
}

// withLoad starts capture, then the load generator 300 ms later, and stops capture 500 ms after the load ends.
func withLoad(ctx context.Context, rate int, d time.Duration, port int, capture func(context.Context) result) result {
	cctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	done := make(chan result, 1)
	go func() { done <- capture(cctx) }()

	time.Sleep(300 * time.Millisecond)
	wait, err := startLoadgen(rate, d-800*time.Millisecond, port)
	sent := -1
	if err != nil {
		fmt.Println("load generator not started:", err)
	} else if sent, err = wait(); err != nil {
		fmt.Println("load generator:", err)
	}
	r := <-done
	r.loadSent, r.rate = sent, rate
	return r
}

func matrix(ctx context.Context, rates []int, d time.Duration, snaplen, port int) {
	var results []result
	for _, rate := range rates {
		for _, c := range []string{"gopacket", "tcpdump"} {
			if ctx.Err() != nil {
				return
			}
			fmt.Printf("running %-8s at %6d datagrams/s for %s ...\n", c, rate, d)
			capture := func(cctx context.Context) result { return runTcpdump(cctx, port) }
			if c == "gopacket" {
				capture = func(cctx context.Context) result { return runGopacket(cctx, snaplen, port) }
			}
			results = append(results, withLoad(ctx, rate, d, port, capture))
		}
	}

	fmt.Println("\n==================== results ====================")
	fmt.Println("rate/s    collector  load sent  load seen / expected   other pkts  drops  errors   CPU ms  % of a core  µs/pkt")
	for _, r := range results {
		drops := "?"
		if r.drops >= 0 {
			drops = strconv.Itoa(r.drops)
		}
		fmt.Printf("%-9d %-10s %9d  %9d / %-9d %6.1f%%  %10d  %5s  %6d  %7.0f  %10.1f%%  %6.2f\n",
			r.rate, r.collector, r.loadSent, r.loadSeen, 2*r.loadSent, pct(r.loadSeen, 2*r.loadSent),
			r.packets-r.loadSeen, drops, r.errorsSeen,
			float64(r.cpu.total().Microseconds())/1000, 100*r.cpu.total().Seconds()/r.wall.Seconds(),
			float64(r.cpu.total().Microseconds())/float64(max(r.packets, 1)))
	}
	fmt.Println("expected = 2 × sent, because PKTAP sees each loopback datagram leaving (lo0 out) and arriving (lo0 in).")
	fmt.Println("tcpdump CPU = tcpdump process + this process reading and parsing its lines.")

	for _, r := range results {
		if r.collector == "gopacket" && len(r.extras) > 0 {
			printExtras(r.extras)
			break
		}
	}
}

func compareRun(ctx context.Context, rate int, d time.Duration, snaplen, port int) {
	var gp, td []pkt
	withLoad(ctx, rate, d, port, func(cctx context.Context) result {
		var mu sync.Mutex
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = captureGopacket(cctx, snaplen, func(p pkt) { mu.Lock(); gp = append(gp, p); mu.Unlock() }, func(error) {})
		}()
		go func() {
			defer wg.Done()
			_, _ = captureTcpdump(cctx, func(p pkt) { mu.Lock(); td = append(td, p); mu.Unlock() })
		}()
		wg.Wait()
		return result{}
	})
	reportMatches(gp, td, matchPackets(gp, td, 5*time.Millisecond))
}

// ---------------------------------------------------------------- gopacket

func openPktap(snaplen int) (*pcap.Handle, error) {
	in, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	defer in.CleanUp()
	for _, step := range []error{
		in.SetSnapLen(snaplen),
		in.SetPromisc(false),
		in.SetTimeout(100 * time.Millisecond),
		in.SetImmediateMode(true), // same latency as tcpdump -l
		in.SetWantPktap(true),     // the call scratch/pktap-probe was missing
	} {
		if step != nil {
			return nil, step
		}
	}
	return in.Activate()
}

func captureGopacket(ctx context.Context, snaplen int, emit func(pkt), decodeErr func(error)) (*pcap.Stats, error) {
	h, err := openPktap(snaplen)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", iface, err)
	}
	defer h.Close()
	if h.LinkType() != layers.LinkTypeApplePKTAP {
		return nil, fmt.Errorf("link type %s, want ApplePKTAP: pcap_set_want_pktap had no effect", h.LinkType())
	}

	var hdr layers.PktapV1
	for ctx.Err() == nil {
		data, ci, err := h.ZeroCopyReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		if err != nil {
			return nil, err
		}
		p, err := decodePktap(&hdr, data, ci)
		if err != nil {
			decodeErr(err)
			continue
		}
		emit(p)
	}
	return h.Stats()
}

func decodePktap(hdr *layers.PktapV1, data []byte, ci gopacket.CaptureInfo) (pkt, error) {
	if err := hdr.DecodeFromBytes(data, gopacket.NilDecodeFeedback); err != nil {
		return pkt{}, err
	}
	p := pkt{
		ts:        ci.Timestamp,
		iface:     hdr.InterfaceName,
		proc:      hdr.CommandName,
		pid:       hdr.PID,
		dir:       Direction(hdr.Direction().String()),
		epid:      hdr.EffectivePID,
		ecomm:     hdr.EffectiveCommandName,
		flags:     hdr.Flags,
		svc:       hdr.ServiceClass.String(),
		caplen:    ci.CaptureLength,
		hdrLength: hdr.HeaderLength,
	}
	// The rest of struct pktap_header (xnu bsd/net/pktap.h) that gopacket does not decode.
	if len(data) >= 156 {
		p.flowid = binary.LittleEndian.Uint32(data[0x6C:0x70])
		p.uuid = uuidString(data[0x7C:0x8C])
		p.euuid = uuidString(data[0x8C:0x9C])
	}
	if p.pid == noPID || (p.pid == 0 && p.proc == "") {
		p.pid, p.proc, p.uuid = 0, "", ""
	}
	if p.epid == noPID {
		p.epid, p.ecomm, p.euuid = 0, "", ""
	}

	ip := data[hdr.HeaderLength:]
	pre := int(hdr.LinkLayerHeaderLength)
	if pre <= len(ip) {
		ip = ip[pre:]
	}
	p.wireLen = ci.Length - int(hdr.HeaderLength) - pre
	if !parseIP(&p, ip) {
		return pkt{}, fmt.Errorf("not IP (dlt %d, %d bytes)", hdr.DLT, len(ip))
	}
	return p, nil
}

func uuidString(b []byte) string {
	zero := true
	for _, c := range b {
		if c != 0 {
			zero = false
			break
		}
	}
	if zero {
		return ""
	}
	s := hex.EncodeToString(b)
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

// parseIP fills addresses, protocol and the same length tcpdump -q prints.
func parseIP(p *pkt, b []byte) bool {
	if len(b) < 1 {
		return false
	}
	var src, dst netip.Addr
	var proto byte
	var l4 []byte
	var payloadLen int
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return false
		}
		ihl := int(b[0]&0x0f) * 4
		proto = b[9]
		p.ipVer, p.ipLenField = 4, int(binary.BigEndian.Uint16(b[2:4]))
		src = netip.AddrFrom4([4]byte(b[12:16]))
		dst = netip.AddrFrom4([4]byte(b[16:20]))
		payloadLen = int(binary.BigEndian.Uint16(b[2:4])) - ihl
		if ihl <= len(b) {
			l4 = b[ihl:]
		}
	case 6:
		if len(b) < 40 {
			return false
		}
		proto = b[6]
		p.ipVer, p.ipLenField = 6, int(binary.BigEndian.Uint16(b[4:6]))
		src = netip.AddrFrom16([16]byte(b[8:24]))
		dst = netip.AddrFrom16([16]byte(b[24:40]))
		payloadLen = int(binary.BigEndian.Uint16(b[4:6]))
		l4 = b[40:]
	default:
		return false
	}
	var sport, dport uint16
	switch proto {
	case 6:
		p.proto = TCP
		if len(l4) >= 13 {
			sport, dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
			p.length = payloadLen - int(l4[12]>>4)*4
		}
	case 17:
		p.proto = UDP
		if len(l4) >= 8 {
			sport, dport = binary.BigEndian.Uint16(l4[0:2]), binary.BigEndian.Uint16(l4[2:4])
			p.length = int(binary.BigEndian.Uint16(l4[4:6])) - 8
		}
	case 1:
		p.proto, p.length = ICMP, payloadLen
	case 58:
		p.proto, p.length = ICMPv6, payloadLen
	case 50:
		p.proto, p.length = ESP, payloadLen
	default:
		p.length = payloadLen
	}
	p.src = netip.AddrPortFrom(src, sport)
	p.dst = netip.AddrPortFrom(dst, dport)
	return true
}

type rusage struct{ user, sys time.Duration }

func selfUsage() rusage {
	var r syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &r)
	return rusage{time.Duration(r.Utime.Nano()), time.Duration(r.Stime.Nano())}
}

func (a rusage) sub(b rusage) rusage  { return rusage{a.user - b.user, a.sys - b.sys} }
func (a rusage) total() time.Duration { return a.user + a.sys }

func runGopacket(ctx context.Context, snaplen, port int) result {
	r := result{collector: "gopacket"}
	before, start := selfUsage(), time.Now()
	st, err := captureGopacket(ctx, snaplen, func(p pkt) {
		r.packets++
		if isLoad(p, port) {
			r.loadSeen++
		} else if len(r.extras) < 2000 {
			r.extras = append(r.extras, p)
		}
	}, func(error) { r.errorsSeen++ })
	r.cpu, r.wall = selfUsage().sub(before), time.Since(start)
	r.drops = -1
	if err != nil {
		fmt.Println("gopacket:", err)
		return r
	}
	r.drops = st.PacketsDropped + st.PacketsIfDropped
	return r
}

// ---------------------------------------------------------------- tcpdump

type tcpdumpRun struct {
	lines, rejected int
	self, child     rusage
	stderr          string
}

func captureTcpdump(ctx context.Context, emit func(pkt)) (tcpdumpRun, error) {
	var r tcpdumpRun
	cmd := exec.CommandContext(ctx, "/usr/sbin/tcpdump", tcpdumpArgs...)
	cmd.Cancel = func() error { return cmd.Process.Signal(os.Interrupt) } // lets tcpdump print its drop stats
	cmd.WaitDelay = 3 * time.Second
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return r, err
	}
	before := selfUsage()
	if err := cmd.Start(); err != nil {
		return r, err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		r.lines++
		ev, ok := parseTcpdumpLine(sc.Text())
		if !ok {
			r.rejected++
			continue
		}
		emit(pkt{ts: ev.ObservedAt, iface: ev.Interface, proc: ev.Process, pid: ev.PID, uuid: ev.ProcessUUID,
			dir: ev.Direction, proto: ev.Protocol, src: ev.Src, dst: ev.Dst, length: ev.Length})
	}
	_ = cmd.Wait()
	r.self = selfUsage().sub(before)
	if ru, ok := cmd.ProcessState.SysUsage().(*syscall.Rusage); ok {
		r.child = rusage{time.Duration(ru.Utime.Nano()), time.Duration(ru.Stime.Nano())}
	}
	r.stderr = stderr.String()
	return r, nil
}

var droppedRe = regexp.MustCompile(`(\d+) packets? dropped by kernel`)

func runTcpdump(ctx context.Context, port int) result {
	r := result{collector: "tcpdump", drops: -1}
	start := time.Now()
	run, err := captureTcpdump(ctx, func(p pkt) {
		r.packets++
		if isLoad(p, port) {
			r.loadSeen++
		}
	})
	r.wall = time.Since(start)
	if err != nil {
		fmt.Println("tcpdump:", err)
		return r
	}
	r.errorsSeen = run.rejected
	r.cpu = rusage{run.child.user + run.self.user, run.child.sys + run.self.sys}
	if m := droppedRe.FindStringSubmatch(run.stderr); m != nil {
		r.drops, _ = strconv.Atoi(m[1])
	}
	return r
}

// ---------------------------------------------------------------- report helpers

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

func printTop(title string, m map[string]int, n int) {
	type kv struct {
		k string
		v int
	}
	var list []kv
	for k, v := range m {
		list = append(list, kv{k, v})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].v > list[j].v })
	if title != "" && len(list) > 0 {
		fmt.Println(title + ":")
	}
	for i, e := range list {
		if i == n {
			break
		}
		fmt.Printf("  %6d  %s\n", e.v, e.k)
	}
}

// printExtras shows what gopacket gives beyond tcpdump -k INPDU.
func printExtras(ps []pkt) {
	if len(ps) == 0 {
		return
	}
	var delegated, withEUUID, longName, flowid, hdr156 int
	flagNames := map[string]int{}
	ifaces := map[string]int{}
	for _, p := range ps {
		if p.flags&0x4 != 0 || (p.epid != 0 && p.epid != p.pid) {
			delegated++
		}
		if p.euuid != "" && p.euuid != p.uuid {
			withEUUID++
		}
		if len(p.proc) >= 16 {
			longName++
		}
		if p.flowid != 0 {
			flowid++
		}
		if p.hdrLength == 156 {
			hdr156++
		}
		ifaces[p.iface]++
		for bit, name := range map[uint32]string{0x4: "PROC_DELEGATED", 0x8: "IF_DELEGATED", 0x4000: "NEW_FLOW",
			0x8000: "REXMIT", 0x10000: "KEEP_ALIVE", 0x20000: "SOCKET", 0x80000: "V2_HDR", 0x100000: "WAKE_PKT"} {
			if p.flags&bit != 0 {
				flagNames[name]++
			}
		}
	}
	fmt.Printf("\nextra metadata in the first %d non-load packets (gopacket):\n", len(ps))
	fmt.Printf("  header length 156 (v1): %d\n", hdr156)
	fmt.Printf("  delegated (PROC_DELEGATED or a real epid != pid): %d\n", delegated)
	fmt.Printf("  effective UUID differs from UUID: %d\n", withEUUID)
	fmt.Printf("  non-zero flow id: %d\n", flowid)
	fmt.Printf("  process name 16 chars or longer (likely truncated): %d\n", longName)
	printTop("  flags seen", flagNames, 10)
	printTop("  interfaces", ifaces, 8)

	fmt.Println("\nsample packets (metadata only):")
	shown := 0
	for _, p := range ps {
		if shown == 6 {
			break
		}
		if p.proc == "" {
			continue
		}
		fmt.Printf("  %s %-6s %-3s %s:%d uuid=%s | eproc %s:%d euuid=%s | flow %#x svc %s flags %#x | %s %s>%s len %d\n",
			p.ts.Format("15:04:05.000000"), p.iface, p.dir, p.proc, p.pid, short(p.uuid), p.ecomm, p.epid, short(p.euuid),
			p.flowid, p.svc, p.flags, p.proto, p.src, p.dst, p.length)
		shown++
	}
	for _, p := range ps {
		if p.epid != 0 && p.epid != p.pid {
			fmt.Printf("  delegated example: %s:%d on behalf of %s:%d (%s %s>%s)\n", p.proc, p.pid, p.ecomm, p.epid, p.iface, p.src, p.dst)
			break
		}
	}
}

func short(u string) string {
	if len(u) > 8 {
		return u[:8]
	}
	return u
}
