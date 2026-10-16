# WhoTracksMe — working reference

Distilled 14 October 2026 from the Perplexity and Gemini research chats.
`README.md` is the product plan (milestones, privacy rules, release checklist).
This file is the lookup sheet for facts and decisions while you write the code.

No implementation lives here. The parser spec is `internal/collector/lsof_parser_test.go`.

## 1. What this project is

A local, observe-only network monitor for your own Mac.

A Go process samples sockets and, later, traffic counters. It stores metadata in SQLite and shows it on a loopback HTMX page at `http://127.0.0.1:8080`. The first useful question is: which processes are talking to which IPs, what is new, and which processes suddenly send much more than usual.

The earlier idea — a Python FastAPI “privacy dashboard” with browser fingerprinting, WebRTC leak tests, and a privacy score — is parked. The browser extension, DNS-log correlation, and Linux/eBPF collector come after the Mac collector is useful on its own.

Version 1 records metadata. It does not read TLS payloads, cookies, tokens, or URL query strings, and it does not block traffic. Packet capture does not change that: modern TLS hides the body. Section 17 is the decision record from the Wireshark / `nettop` / proxy discussion.

## 2. Where the repo is now

```text
cmd/whotracksme/          empty; binary entry comes later
internal/collector/       SocketEvent types, unfinished parser, tests
internal/model/           empty
internal/store/           empty
internal/enrich/          empty
internal/detect/          empty
internal/web/             empty
internal/config/          empty
internal/reconsile/       empty (README spells this reconcile)
migrations/               empty
packaging/launchd/        empty
```

`go test ./internal/collector -run TestParseLsofStream` is the check for the parser. The test feeds `lsof -F` lines into the parser and compares `SocketEvent` values. It does not spawn `lsof`. The module path is `whotracksme` (`go.mod`). Run tests from the repo root.

## 3. What an observation is allowed to mean

| You saw                   | You may say                                          | You may not say                               |
|---------------------------|------------------------------------------------------|-----------------------------------------------|
| `lsof` snapshot           | This socket was visible at this time                 | Every connection was captured                 |
| `nettop` byte increase    | This process transmitted more bytes in this interval | It sent a password or a particular file       |
| New remote IP             | This process has not been seen contacting that IP    | The destination is malicious                  |
| PTR / reverse DNS         | The IP has this reverse name                         | The app requested that hostname               |
| DNS log near a connection | A domain resolved to that IP around then             | This process definitely looked up that domain |
| Tracker-list hit          | A list labels this domain as tracking-related        | Personal data was exfiltrated                 |

Polling misses anything that opens and closes between samples. Shared CDN IPs, VPNs, proxies, and browser helper processes make attribution fuzzy. Record that. UDP sockets often have no remote peer; store them as sockets with an unknown destination.

Findings should read like “unusual outbound traffic — inspect”, with the evidence attached.

## 4. macOS tools

Use these on your own machine. `man lsof` and `man nettop` on this Mac win over online copies.

### Use now

| Tool                                       | What it gives you                                                                                                                                                         |
|--------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `lsof -i -n -P`                            | Point-in-time sockets: process, PID, user, FD, protocol, endpoints, TCP state. No byte counters.                                                                          |
| `lsof -i -n -P -F pcufPTn`                 | Socket inventory: listeners, idle sockets, full command, user, TCP state. Not the live feed.                                                                              |
| `/usr/sbin/tcpdump -i pktap,en0 -n -k NPD -l` | Live feed that actually includes a PID on this Mac. Parse the summary line. Do not use `gopacket` on this interface for attribution.                                      |
| `netstat`                                  | Skip it. macOS `netstat` lists addresses and states and does not attach a PID.                                                                                            |
| `nettop`                                   | Calibration only. Compare one short sample with `pktap` byte sums. `nettop -L 0` is the fallback live feed if `pktap` metadata is unusable.                               |

The dashboard process stays unprivileged. A separate helper opens `pktap`. Root sees more `lsof` descriptors; do not run the HTTP server as root to get them.

Cadence:

- `pktap` runs for the life of the collector.
- `lsof` about once a minute, for listeners and idle sockets.
- `nettop` only during the calibration experiment in section 8.

### Useful for understanding, not for the collector

| Tool                                  | What it is for                                                                                                          |
|---------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| `tcpdump -i en0` / BPF                | Raw frames. No process id unless you capture on `pktap`.                                                                |
| `tcpdump -i pktap0`                   | Packets plus an Apple metadata header (PID, process name, interface). Passive. Needs root. Wireshark understands PKTAP. |
| `pktmon`                              | Apple’s packet monitor; can attach process metadata. Passive.                                                           |
| `sc_usage -c network`                 | Live network-related syscalls.                                                                                          |
| `dtrace` / `dtruss`                   | Kernel syscall probes. Tracing system binaries needs SIP exceptions.                                                    |
| `log stream` on `mDNSResponder`       | DNS questions and answers the system resolver parsed.                                                                  |
| `log stream` on `com.apple.CFNetwork` | Apple networking-stack diagnostics.                                                                                     |
| Wireshark                             | Compare one short capture of your own traffic with an `lsof` snapshot. TLS payloads stay encrypted.                     |

After a short capture, pick one connection and write down process, local endpoint, remote endpoint, and protocol, plus what the capture cannot tell you.

### Blocking, later, and only on your own machine

Version 1 does not block. If you add enforcement later, these are the real options:

| Approach                                 | Layer          | Process identity                      | Entitlement                 | Cost                                                                       |
|------------------------------------------|----------------|---------------------------------------|-----------------------------|----------------------------------------------------------------------------|
| Network Extension `NEFilterDataProvider` | Socket / flow  | Bundle id, PID, signature             | Yes, paid developer account | Medium. Official path. Verdicts are allow, drop, or remediate.             |
| `pf` via `pfctl`                         | IP / TCP / UDP | User id only                          | No, needs root              | Low. Drops or rejects matching packets. No app path.                       |
| `pf` redirect plus a local proxy         | Application    | Indirect, via the redirected port     | No, needs root              | High. HTTPS inspection needs a local CA, or you stop at SNI / ClientHello. |
| Local DNS resolver                       | DNS            | Only if you join `mDNSResponder` logs | No                          | Low. Misses hardcoded IPs and browsers that use their own DoH.             |

Little Snitch / Portmaster-level visibility is the Network Extension, and it is a Swift/Objective-C system extension plus your Go dashboard. Build it only after the polling collector is already useful.

## 5. `lsof` field mode

Human table columns shift. `com.docke` is a truncated name, and a command with spaces breaks `strings.Fields`. Do not parse the aligned table.

Command:

```bash
lsof -i -n -P -F pcufPTn
```

`-i` internet files, `-n` no DNS, `-P` numeric ports, `-F` field mode.

Each output line is one character of tag plus the value. A new `p` line starts a process. A new `f` line starts a socket on the current process.

| Tag | Field                    | Example                                                      |
|-----|--------------------------|--------------------------------------------------------------|
| `p` | PID                      | `p59292`                                                     |
| `c` | Command, spaces included | `czen`                                                       |
| `u` | User                     | `upieczasz`                                                  |
| `f` | FD and access mode       | `f115u`                                                      |
| `P` | Protocol                 | `PTCP`, `PUDP`, `PICMP`, `PICMPV6`                           |
| `T` | TCP state                | `TST=ESTABLISHED`, `TST=LISTEN`                              |
| `n` | Endpoints                | `n10.2.0.2:50867->66.203.125.13:443` or `n*:53900` or `n*:*` |

Dropped on purpose:

- `t` (the text `IPv4` / `IPv6`). `netip.Addr.Is4` / `Is6` covers it. A wildcard `*:` has no address, so IP family can be unknown. That is fine.
- `d` (kernel socket pointer such as `0xb7141f33f5e892bd`). Only useful against kernel dumps.

Measured on this Mac, TCP only:

| Invocation                      | Lines |
|---------------------------------|-------|
| `lsof -iTCP -n -P -F`           | 462   |
| `lsof -iTCP -n -P -F pcuftPTnd` | 297   |
| `lsof -iTCP -n -P -F T`         | 143   |

Bare `-F` on this macOS includes TCP state. Both `lsof -iTCP -n -P -F \| grep '^T'` and `lsof -iTCP -n -P -F T \| grep '^T'` returned 108. The explicit list is for a smaller, predictable stream, not because bare `-F` hides state.

One chat reply wrote `-F pcuPTn`. That string drops `f`. Keep `f`. The collector command is `-F pcufPTn`. `lsof` also emits `p` and `f` as structural markers even for a short list such as `-F T`.

`README.md` mentions `-F0` (NUL-separated fields). Newline mode matches the tests. NUL is the upgrade if a command name can contain a newline.

### FD column

`115u` is descriptor 115, access `u`.

| Piece                      | Meaning                                                        |
|----------------------------|----------------------------------------------------------------|
| `0`, `1`, `2`              | stdin, stdout, stderr                                          |
| `3` and up                 | Ordinary descriptors: files, pipes, sockets                    |
| trailing `r` / `w` / `u`   | read, write, read-write                                        |
| `cwd`, `rtd`, `txt`, `mem` | Not a numeric socket FD. `-i` output should not produce these. |

### PID

A live PID is never negative. PID 0 is the kernel, not a user process. `uint32` is the right field. POSIX `pid_t` is signed so that `-1` can mean “error” or, in `kill` / `waitpid`, “this process group”. You will not see a negative PID in `lsof`.

### Ports and addresses

Ports are `uint16` (0–65535). `uint8` truncates. Port `0` and `*` both mean “no specific port”; the tests expect port `0` for `*:*`.

`netip.Addr` is a comparable value. Use it as a map key. An invalid or wildcard host stays the zero `Addr` plus `IsWildcard` when the text was `*`.

Endpoint shapes:

| `n` value                           | Local                       | Remote                  |
|-------------------------------------|-----------------------------|-------------------------|
| `10.2.0.2:50867->66.203.125.13:443` | that address and port       | that address and port   |
| `*:50265`                           | wildcard, port 50265        | nil                     |
| `*:*`                               | wildcard, port 0            | nil                     |
| `127.0.0.1:8080`                    | that address, no remote     | nil (listen or unbound) |
| `[::1]:3000->[::1]:54321`           | strip brackets, parse `::1` | same                    |

ICMP lines (`*:*`, `ICMP` / `ICMPV6`) follow the same “no remote” path. State stays empty when there is no `TST=` line.

A line with length 0 is blank. Length 1 is a bare tag such as `f` with an empty value. Skip both. `line[0]` on an empty string panics. Unknown tags (`x...`) are ignored. A socket with no protocol is not emitted.

Process fields (`c`, `u`) apply to every following FD until the next `p`. Flush the open socket when the next `p` or `f` arrives, and once more at end of input.

## 6. Types already in `internal/collector`

`SocketEvent`: observed time, command, PID, user, FD number, access rune, protocol, TCP state, local endpoint, optional remote endpoint.

`SocketEndpoint`: `netip.Addr`, `uint16` port, wildcard flag.

Protocols: `TCP`, `UDP`, `ICMP`, `ICMPV6`.
States used by the tests: `ESTABLISHED`, `LISTEN`, empty. The type also names `CLOSE_WAIT`, `TIME_WAIT`, `SYN_SENT` for later real output.

`IsIPv4` / `IsIPv6` look at local, then remote. Both are false for a pure wildcard socket.

## 7. Parser cases the tests already lock

`TestParseLsofStream` in `internal/collector/lsof_parser_test.go`:

1. Established IPv4 TCP. `zen` / pid 59292 / fd `115u` / `10.2.0.2:50867 -> 66.203.125.13:443`.
2. Listening TCP. `rapportd` / `*:50265` / `LISTEN` / remote nil.
3. UDP `*:*`. Protocol UDP, empty state, port 0, wildcard, remote nil.
4. IPv6 with brackets. `[::1]:3000->[::1]:54321`, access `w`.
5. Two sockets on pid 500, then a UDP socket on pid 600. Command and user must not leak across the `p` boundary.
6. Blank lines, an unknown tag, and a bare `f` are skipped. The following `f10u` / `PTCP` / `*:443` still parses. That listen line has no `TST=`, so state is empty.

Fixed timestamp in the test: `2026-10-14 12:00:00 UTC`. The parser must take the time from its constructor, not from `time.Now()` inside the parse of a fixture.

`CollectSockets` is separate: it runs `lsof` and feeds the same parser. Tests should keep calling the parser with strings so they stay free of the live process table.

## 8. Sampling experiment before trusting counters

1. Start a small local HTTP server.
2. Hold a client connection for about 30 seconds and confirm PID and endpoints in `lsof`.
3. Send a request that finishes immediately and confirm a 5–10 second poll can miss it.
4. Upload a known dummy size and compare `nettop` with that size, allowing for protocol overhead.

If `nettop` output is not stable, ship connection history first and leave volume alerts out.

## 9. Storage

SQLite, file local to you. PostgreSQL only if you later have several devices or a long multi-writer history.

Open with WAL, a busy timeout, and normal synchronous mode, so the dashboard can read while the collector writes:

```text
file:netwatch.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)
```

One writer. A failed poll is a gap, not “everything disconnected”.

Do not insert a new connection row on every poll. Update a session: first seen, last seen, sample count. Inserting `(observed_at, pid, remote_ip, remote_port)` every tick turns one long Slack socket into hundreds of rows.

Tables to grow into (see `README.md` section 5 for the precise list):

- process instances (PID plus start time when you can get it; a PID is reused)
- connection sessions
- traffic samples (bytes stay NULL when unknown, never a fake 0)
- destination metadata (IP, optional PTR, source, expiry)
- findings
- collector runs (success, duration, error)

Store UTC. Keep evidence JSON for findings. Keep routinely filtered fields as real columns.

Enrichment is a different goroutine from the poll loop. `net.LookupAddr` can block for seconds. Push new IPs to a small worker pool, cache for about a day, and label PTR as a hint. The collector’s own lookups are traffic too; mark them or exclude them.

Driver: `modernc.org/sqlite` (pure Go, no CGO). Handwritten SQL is enough at the start. `sqlc` is optional once the queries settle.

## 10. Libraries

| Job                    | Use                                                                                                                                                      |
|------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| HTTP + HTML            | `net/http`, `html/template`                                                                                                                              |
| SQLite                 | `database/sql` + `modernc.org/sqlite`                                                                                                                    |
| Addresses              | `net/netip`                                                                                                                                              |
| Processes              | `os/exec` for `lsof` / `nettop`. `github.com/shirou/gopsutil/v3/process` only if you need command line, CPU, or parent PID without parsing another tool. |
| GeoIP, when you add it | `github.com/oschwald/geoip2-golang` and a local GeoLite2 file                                                                                            |
| DNS, when you add it   | `github.com/miekg/dns`                                                                                                                                   |
| Scheduling             | `time.Ticker` and `context`. No cron package for a 5-second poll.                                                                                        |
| UI                     | HTML templates, one CSS file, HTMX served by the Go process                                                                                              |
| Router                 | `chi` only if `net/http` gets painful. No Gin, no Echo, no React for this UI.                                                                            |

Offline lists, when enrichment exists: GeoLite2 Country and ASN; a hosts-style tracker list you can name and version (StevenBlack, OISD, or Peter Lowe). A small YAML map for noisy first-party domains (Apple, Google, Cloudflare) so they are not “unknown”.

Do not send every IP to a third-party API.

## 11. Dashboard

HTMX asks the server for an HTML fragment on a timer. Grafana is a later chart add-on, not the product UI.

Pages, when you get there:

- `/` health, visible sockets, new destinations, recent findings
- `/connections` filters
- `/processes` and `/processes/{instance}`
- `/domains`
- `/findings` with acknowledge
- export CSV/JSON for an explicit time range
- pause, retention, delete-all

Pattern: a table with `hx-get` and `hx-trigger="every 5s"`, swapping `innerHTML`. Filtering replaces the results fragment only.

Bind `127.0.0.1` only. Loopback is not a full security boundary: a hostile page in your browser can still call it. Protect anything that pauses, deletes, or acknowledges. No wildcard CORS. Paginate history. Hide the monitor’s own dashboard connections by default.

## 12. Anomaly rules, in this order

Explainable rules only. No machine learning until you have real measurements.

1. New destination for an application. Informational. Suppress the first learning window (README suggests 48 hours).
2. Burst of new sessions or distinct IPs. Say the count is approximate, because sampling is incomplete.
3. Upload spike, only after `nettop` is validated. Compare a fixed window with the process’s own history, with a minimum absolute size.
4. Tracker-list match, only on a real domain signal. A PTR name is not that signal.
5. Later: new category for a process, unusual country/ASN, DNS resolver change, NXDOMAIN bursts, random-looking DNS labels, off-hours activity.

Each finding stores detector name, severity, what changed, window, identity and confidence, measured values, baseline size, source, coverage gaps, and a reason it might be normal (update, sync, backup, CDN, VPN).

## 13. Build order

Section 17 is the collection split. Short version:

1. Finish the `lsof` parser until `TestParseLsofStream` passes. The listener inventory still needs it.
2. A throwaway `pktap` probe, separate from the daemon: print PID, short name, direction, 5-tuple, and length for a few seconds, then discard the packet. Confirm the header against this Mac, not against a copied struct.
3. One calibration: those lengths versus a short `nettop` sample. Write down the gap (headers, retransmits, drops).
4. Store sessions from the probe plus a slow `lsof` pass. Answer “which processes contacted the most distinct remote IPs?” including a connection that lasted under a second.
5. HTMX dashboard on `127.0.0.1:8080`, reading the database. It does not capture.
6. New-destination findings, then volume findings.
7. Pause, export, delete, retention. The capture helper is the privileged process. The UI is not.

Then, not before:

- cached PTR lookups, off by default
- local GeoIP / ASN
- AdGuard Home or Pi-hole query import (your VPS can host that). DNS logs still do not prove which process queried
- browser extension: page domain, third-party domains, resource type, blocked-or-not. No cookie values, bodies, or form data
- Linux collector behind the same models: `/proc` snapshots first, then a small eBPF program via `cilium/ebpf` and `bpf2go`. A Linux VM sees the VM’s traffic, not the Mac’s
- Grafana for low-cardinality health metrics only. Do not put every PID, IP, or domain in a Prometheus label

## 14. Home network and VPS

Out of the MVP. Kept here so the earlier notes are not lost.

The dashboard stays on the laptop. Do not port-forward it. Trusted LAN, IoT VLAN, and guest VLAN are router work: block IoT from the trusted LAN, disable UPnP and WAN admin, keep firmware updated. Local DNS filtering (Pi-hole, AdGuard Home, Unbound) belongs on the home network or a private path, not as an open recursive resolver on the public internet.

The VPS does not see Mac traffic by existing. Later uses: private DNS query logs, a private test destination, or an authenticated multi-device archive. If the app is ever on the VPS, bind it to localhost and put Caddy or Nginx in front, with SSH keys and a firewall limited to 80, 443, and SSH from your IP.

## 15. Watch and read while building

Watch, then do the exercise the same session. Skip general Go beginner courses.

| When                                  | Watch                                                                                                                      | Then do                                                                                                                      |
|---------------------------------------|----------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| First                                 | Practical Networking — DNS, HTTP, TLS, DHCP. DNS section near 05:04                                                        | `lsof -nP -i` on one connection. Write what it shows and what it cannot.                                                     |
| Second                                | Wireshark beginner capture tutorial                                                                                        | Short capture on your Mac. Filters `dns`, `tcp`, `tls`. Compare with `lsof`.                                                 |
| After SQLite history works            | Intro to Go and HTMX (~10 min, Gin + HTMX + SQLite)                                                                        | `/connections` plus a fragment refreshed every 5 seconds. Standard `net/http` is enough; Gin is optional in that video only. |
| If the fragment flow is still unclear | Modern Web With Go and HTMX                                                                                                | Process and time filters that swap one section.                                                                              |
| Before any Linux work                 | Liz Rice, GOTO: A Beginner’s Guide to eBPF Programming with Go (~36 min). Programs/maps ~06:43, attach ~09:56, maps ~24:40 | Official ebpf-go getting-started tutorial, one tiny program in a Linux VM, same observation types as the Mac collector.      |

There is no good video for `lsof -F`, `nettop` flags, or launchd. Use the manuals.

Read when the milestone needs it (links are in `README.md` section 7):

- `man lsof`, `lsof -F '?'`, and the upstream lsof man page
- `man nettop` on this Mac
- `os/exec`, `net/netip`, Go database/sql, `modernc.org/sqlite`, SQLite WAL
- `html/template`, `net/http`, HTMX docs
- Apple launchd guide, `man launchctl`, `man launchd.plist`
- Wireshark TLS page, so the payload limit stays obvious
- Later: ebpf-go getting started, cilium/ebpf, `proc_net(5)`. `/proc/<pid>/net/dev` is the network namespace, not that process’s byte counter
- Later: WebExtensions `webRequest`. uBlock’s logger is a reference UI; your extension cannot read uBlock’s private events

## 16. Privacy rules for every later feature

- Metadata only. No payloads, cookies, tokens, passwords, message bodies, or full URLs with query strings.
- Local by default. Pause and delete-all must exist.
- Every alert has evidence and a confidence. Nothing is blocked automatically in v1.
- Label PTR, GeoIP, and tracker-list hits with their source. Do not present them as observed hostnames or as proof of exfiltration.

## 17. Traffic analysis plan

`pktap` replaces `nettop` as the live feed. It does not replace `lsof`, and it does not reveal request bodies.

Tested on this Mac, 14 Oct 2026, as root. `gopacket` `OpenLive("pktap,en0")` returned link type Raw (12). The only datalink offered was RAW. The buffer started with an IPv4 header and contained no PKTAP header, so the PID was always 0. Requested snaplen 128 was ignored (`SnapLen` reported 524288) and full UDP payloads were delivered. Do not build the collector on that API, and do not keep those buffers.

`/usr/sbin/tcpdump -i pktap,en0 -n -k NPD -l` on the same interface printed process name, PID, and direction. The name was not truncated to 16 characters. That text line is the live feed. With a VPN up, the process on the packet was the VPN client, not the app that opened the socket. `lsof` is still how you see those apps.

| Question | `pktap` | `lsof` |
|---|---|---|
| A short connection that sends a packet | Yes, when the capture is running | Often missed by a poll |
| Bytes on the wire | Sum of captured lengths. Includes headers and retransmits. Drops if the buffer overruns | No |
| PID and process | PID, sometimes missing. Name truncated | Full command, user, FD |
| TCP state, idle socket, `LISTEN` on localhost versus every interface | No, until some packet arrives | Yes |
| HTTP path, headers, JSON, or “my email was in the body” | No | No |

A SYN-only filter is the wrong default. It catches TCP connection attempts and throws away the traffic you would count. Keep the packets long enough to read the header and the length.

`nettop` is the ruler for one experiment: run it beside the probe and write down how the two byte totals differ. If `pktap` cannot supply a PID, use `nettop -L 0` as the live feed instead of inventing one. `netstat` stays out. It has no PID on macOS.

Endpoint Security and a Network Extension are the later listen-without-sniffing path. They need an Apple entitlement. They are not the next task.

### What stays outside the daemon

Inspect one app by hand, after a finding, and do not write the result into SQLite.

| Tool | Sees bodies when | Fails when |
|---|---|---|
| TLS key log plus Wireshark or `tshark` | You started that app and its TLS library writes session keys | The app ignores the variable. Chrome and many Electron apps can. A lot of native apps cannot |
| mitmproxy | The app uses your proxy and trusts your CA | Certificate pinning, QUIC, raw TCP, and clients that ignore the system proxy. The failure mode is a dropped request, not a crashed app |
| Frida | You attach and the plaintext still lives in a function you can name | SIP, Hardened Runtime, stripped static TLS. A bad hook crashes the process. Hooks break on app updates |

Use a proxy before Frida. Frida is a one-off debugger, not a collector.

### Tackle next

1. A parser for one `tcpdump -k NPD` line: process name, PID, direction. Fixture from the shape `(proc name:pid, dir)`, no live capture in the test.
2. A root helper that runs `/usr/sbin/tcpdump` with those flags and feeds the parser. It stores the summary, not the packet.
3. Keep the `lsof` inventory beside it. Under a VPN the packet’s process is the VPN.

The `gopacket` PKTAP struct from the write-up does not match what this OS returns. `scratch/pktap-probe` is the failed experiment. Leave it out of the daemon.
