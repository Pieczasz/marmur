package main

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

type pair struct {
	g, t int
	dt   time.Duration
}

// matchPackets pairs gopacket and tcpdump records of the same packet.
// Candidates share interface, endpoints and direction and lie within window.
// A candidate with the same length wins over a closer one with a different length,
// so two packets of one flow a few microseconds apart are not cross-matched.
func matchPackets(gp, td []pkt, window time.Duration) []pair {
	type key struct {
		iface    string
		src, dst netip.AddrPort
		dir      Direction
	}
	pool := map[key][]int{}
	for i, p := range td {
		k := key{p.iface, p.src, p.dst, p.dir}
		pool[k] = append(pool[k], i)
	}
	used := make([]bool, len(td))
	var pairs []pair
	for gi, g := range gp {
		best, bestDt, bestSameLen := -1, time.Duration(0), false
		for _, ti := range pool[key{g.iface, g.src, g.dst, g.dir}] {
			if used[ti] {
				continue
			}
			dt := absDur(g.ts.Sub(td[ti].ts))
			if dt > window {
				continue
			}
			sameLen := td[ti].length == g.length
			if best < 0 || (sameLen && !bestSameLen) || (sameLen == bestSameLen && dt < bestDt) {
				best, bestDt, bestSameLen = ti, dt, sameLen
			}
		}
		if best >= 0 {
			used[best] = true
			pairs = append(pairs, pair{gi, best, bestDt})
		}
	}
	return pairs
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

func reportMatches(gp, td []pkt, pairs []pair) {
	fmt.Printf("gopacket packets: %d, tcpdump packets: %d\n", len(gp), len(td))
	fmt.Printf("matched: %d  (%.1f%% of gopacket, %.1f%% of tcpdump)\n", len(pairs), pct(len(pairs), len(gp)), pct(len(pairs), len(td)))
	fmt.Printf("only gopacket: %d, only tcpdump: %d\n", len(gp)-len(pairs), len(td)-len(pairs))
	if len(pairs) > 0 {
		dts := make([]time.Duration, len(pairs))
		for i, p := range pairs {
			dts[i] = p.dt
		}
		slices.Sort(dts)
		fmt.Printf("timestamp difference on matched packets: median %s, max %s\n", dts[len(dts)/2], dts[len(dts)-1])
	}

	diff := map[string]int{}
	samples := map[string][]string{}
	for _, p := range pairs {
		g, t := gp[p.g], td[p.t]
		for _, f := range []struct {
			name string
			same bool
			g, t any
		}{
			{"process", g.proc == t.proc, g.proc, t.proc},
			{"pid", g.pid == t.pid, g.pid, t.pid},
			{"uuid", g.uuid == t.uuid, g.uuid, t.uuid},
			{"protocol", g.proto == t.proto, g.proto, t.proto},
			{"length", g.length == t.length, g.length, t.length},
		} {
			if f.same {
				continue
			}
			diff[f.name]++
			if len(samples[f.name]) < 4 {
				samples[f.name] = append(samples[f.name], fmt.Sprintf(
					"    gopacket=%v tcpdump=%v | %s %s %s %s>%s | IPv%d len-field %d, wire %d, caplen %d, flags %#x, proc %s:%d",
					f.g, f.t, g.iface, g.dir, g.proto, g.src, g.dst, g.ipVer, g.ipLenField, g.wireLen, g.caplen, g.flags, g.proc, g.pid))
			}
		}
	}
	if len(diff) == 0 {
		fmt.Println("field disagreements on matched packets: none")
		return
	}
	fmt.Println("field disagreements on matched packets:")
	printTop("", diff, 10)
	for _, name := range []string{"length", "protocol", "process", "pid", "uuid"} {
		if len(samples[name]) > 0 {
			fmt.Printf("  %s examples:\n", name)
			for _, s := range samples[name] {
				fmt.Println(s)
			}
		}
	}
}
