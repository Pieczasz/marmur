# Local Network Observatory — Build Plan

Prepared for Bartłomiej Piekarz • 13 October 2026

## 1. Product decision

Build a background, read-only network monitor for your Mac, with a local Go + HTMX dashboard and SQLite history. Later replace the macOS polling adapter with a Linux collector, then add browser context.

The first useful question is: “Which processes are communicating with which IPs, what is new, and which processes are sending unusually large amounts of traffic?”

This is a metadata observability project, not a firewall, packet-payload recorder, or guaranteed data-loss-prevention system.

### MVP includes

- A privileged `pktap` reader for live traffic: process id, short process name, direction, addresses, and byte counts. Payload bytes are discarded immediately.
- Infrequent `lsof` snapshots for what packets cannot show: listeners, idle sockets, the full command name, user, and TCP state.
- `nettop` only as a calibration check against those byte sums, not as the collector.
- The HTTP dashboard stays unprivileged. It does not open BPF.
- Persistent connection history and process/destination summaries.
- Explainable new-destination and upload-volume findings.
- Optional cached reverse-DNS enrichment, clearly identified as a hint.
- Local dashboard, pause/resume, export, retention and clear-data controls.
- A per-user launchd agent after manual operation is stable.

### Excluded from MVP

- Apple Network/System Extensions, Swift, Xcode entitlements and firewalling.
- Browser extension, fingerprinting detection and automatic tracking attribution.
- Router changes, VPS deployment, public DNS servers or DNS interception.
- TLS interception, session-key collection, payload storage or credential scanning.
- ML, remote IP-intelligence APIs, containers, Grafana and Prometheus.

Start with one Go process and one SQLite file. Add components only when a specific limitation justifies them.

## 2. What the evidence actually means

| Observation | Valid interpretation | Invalid interpretation |
|---|---|---|
| Socket snapshot | A socket with these endpoints was visible at this time | Every connection was captured |
| Process outgoing-byte increase | That process transmitted more bytes during this sampling interval | It sent passwords or a particular file |
| New remote IP | This process has not previously been observed contacting that IP | The destination is malicious |
| Reverse-DNS/PTR name | The IP has this PTR name | This was the hostname the application requested |
| Later DNS-to-IP association | A domain resolved to that IP near this time | This particular process definitely requested that domain |
| Tracker-list match on an observed domain | A specific list labels this domain as tracking-related | Sensitive data was definitely exfiltrated |

TLS hides application contents from passive observation unless appropriate secrets or cooperating application instrumentation are available. Even a deeper OS collector does not automatically decrypt TLS. [web:195]

A packet capture is not a way around that. TLS 1.3 and QUIC hide the HTTP path, headers, and body. Wireshark shows ciphertext, addresses, sizes, and timing. On macOS, `netstat` does not attach a process id; `lsof` does. Reading a body means an app you launched writes its TLS keys, or it trusts a local proxy you configured. Neither belongs in the collector, and neither result is stored. The collector answers who talked to where, and how much. Opening one app by hand comes after a finding.

Polling misses activity between samples. Shared cloud/CDN IPs, VPNs, proxies and browser helper processes complicate attribution. Record uncertainty, not guessed certainty. UDP sockets can lack a fixed remote peer; represent those as sockets with an unknown destination rather than inventing a connection.

Your MVP should say “unusual outbound traffic — inspect” rather than “your email/password was leaked.” Country/ASN are optional context, not maliciousness signals.

## 3. Architecture

```text
tcpdump -k (root)              lsof (user, rare)
process, pid, direction,        listeners, idle sockets,
summary line only               full command, user, TCP state
no packet body kept
       |                              |
       +--------- Go adapters --------+
                       |
               normalized observations
                       |
               snapshot reconciliation
                       |
                SQLite batch writer
                       |
           +-----------+------------+
           |                        |
   baseline/rule evaluation    query layer
           |                        |
       findings              Go net/http
                                    |
                         html/template + HTMX
                         http://127.0.0.1:8080
```

Use native execution on the host. A Docker container on macOS is not the right place to observe native Mac processes.

### Technology choices

- Go standard library: `net/http`, `html/template`, `os/exec`, `context`, `log/slog`, `embed`, `net/netip`, `os/signal`.
- SQLite: `database/sql` + `modernc.org/sqlite`.
- Live capture: a root helper execs `/usr/sbin/tcpdump` with `-k NPD` and parses its summary line. The dashboard does not capture, and it does not link libpcap.
- UI: HTML templates, small CSS file, locally served HTMX. No Node or SPA required. HTMX uses HTML responses and supports periodic polling. [web:189][web:190]
- SQL: handwritten parameterized queries initially; sqlc is an optional later improvement.
- Background lifecycle: foreground Go process managed by launchd, not a self-daemonizing binary. [web:192]
- Collector boundary: OS-specific files/build tags; domain models and analysis must not import platform-specific APIs.

### Repository

```text
cmd/netwatch/main.go
internal/model/                 normalized types
internal/collector/
    collector.go                interfaces and coverage
    lsof_darwin.go              subprocess adapter
    nettop_darwin.go             optional counter adapter
    proc_linux.go               future Linux adapter
    testdata/                   synthetic/sanitized fixtures
internal/reconcile/             snapshot-to-history logic
internal/store/                 SQLite + embedded migrations
internal/detect/                rules + baselines
internal/enrich/                optional PTR cache
internal/web/                   parsers + templates + static files
internal/config/                flags/config defaults
packaging/launchd/              user-agent plist example
migrations/
README.md
```

Keep the interface small: socket snapshots and traffic samples are different inputs. A process counter is not a per-connection counter.

Suggested normalized fields:

- Socket: observed time, source, process instance, PID, process name, optional executable path, socket identifier/FD, protocol, local endpoint, optional remote endpoint, state.
- Traffic sample: observed time, source, process instance, counter scope, incoming/outgoing counter or delta, interval, validity.
- Coverage: last successful poll, error, source version, collection duration, unknown attribution count.

A PID alone is not a stable identity. Prefer PID plus process start time for an instance; record uncertainty if unavailable. Use executable/bundle identity where reliably obtained for an application baseline. Never silently merge unrelated processes just because a short display name matches.

## 4. Install and prove the data sources — first session

Assuming Homebrew already exists:

```bash
brew install go sqlite
go version
sqlite3 --version
command -v lsof
command -v nettop

man lsof
man nettop
man launchctl
man launchd.plist
```

`lsof` and `nettop` normally ship with macOS. The manuals on your own machine take precedence over online examples, especially for nettop flags/output.

Inspect socket output:

```bash
lsof -nP -i
lsof -nP -i -F0pcuftPnT
```

The `-F` output is designed for programmatic parsing; `0` selects NUL-delimited fields. Do not parse aligned display columns. Read the process/file grouping and field definitions before implementing the parser. [web:188]

For nettop, after checking your local manual, try:

```bash
nettop -n -P -L 2
```

Check which byte columns are emitted, whether each row is cumulative or a delta, and how process identity is encoded. Do not assume that two rows from separate invocations share a counter epoch. `-P` process summaries are not remote-endpoint detail. Online nettop manuals can be old. [web:187]

Run both commands as your own user first. Compare what you see with Activity Monitor and, optionally, an already trusted network-monitoring tool. If essential processes are missing, perform a one-off elevated diagnostic only after inspecting the command. Do not make the entire HTTP service root to gain more visibility.

### Experiment

1. Start a tiny local Go HTTP server on another port.
2. Have a separate Go client maintain a connection for 30 seconds.
3. Confirm PID/endpoints appear in lsof.
4. Repeat with a very short request to demonstrate sampling gaps.
5. Upload a known amount of dummy data to your local server.
6. Compare nettop deltas with the expected approximate traffic; account for protocol overhead.

Exit criterion: written notes on exactly what each tool provides and which processes/sockets are not visible. If nettop cannot be parsed reliably, ship connection history first and defer volume alerts.

## 5. Sequential implementation milestones

Effort estimates are planning targets, not promises. Expect roughly 2–4 weeks of part-time work plus baseline observation.

### Milestone A — tested socket parser (1–2 sessions)

Study: lsof field output; Go `os/exec`, `context` and `net/netip`.

Build:

1. Repository and `cmd/netwatch` with a `snapshot` subcommand.
2. Execute lsof with a timeout, explicit arguments and bounded output; no shell string interpolation.
3. Separate subprocess execution from parsing.
4. Parse process/file boundaries, TCP/UDP, IPv4/IPv6 and socket state.
5. Preserve missing fields rather than guessing values.
6. Emit normalized JSON to stdout for debugging.
7. Classify listening, loopback/local and remote endpoints separately. Remote does not automatically mean outbound; direction must be supported by evidence.

Tests: IPv6, wildcard listener, unconnected UDP, multiple FDs, multiple processes, missing permissions, truncated output, nonzero exit with useful diagnostics, empty snapshot.

Done: controlled long-lived test connections are identified correctly; parser tests pass.

### Milestone B — persistence and reconciliation (2–3 sessions)

Study: Go database/sql transactions/cancellation; SQLite WAL and indexes.

Build:

1. Embedded, versioned migrations.
2. Poll every 5 seconds as an initial setting; make it configurable.
3. One writer queue with bounded capacity and batched transactions.
4. Track first/last observed time and sample count for each observed socket session.
5. Do not insert a new connection event on every poll.
6. Only reconcile disappeared sockets after a successful complete-enough snapshot. A failed poll is a gap, not mass disconnection.
7. Record source health, errors and collection durations.

Suggested tables:

- `process_instances`: instance ID, PID, start time when known, display name, optional path, identity confidence.
- `connection_sessions`: process instance, protocol, endpoints, first/last observed, state, observation count, source, inferred-ended time.
- `traffic_samples`: process instance, interval, bytes in/out, scope, source, validity.
- `destination_metadata`: IP, optional PTR, source, queried/expires timestamps.
- `findings`: detector, severity, evidence JSON, baseline details, acknowledgment.
- `collector_runs`: source, start/end, success, coverage and error.

Use UTC timestamps, nullable missing data and indexes for time/process/remote-IP queries. Reserve JSON for evidence, not every routinely queried field.

Enable WAL and foreign keys; configure busy timeout per connection. Start with one SQL connection for simplicity. WAL still permits only one writer at a time. Use an up-to-date SQLite driver; check the engine version with `SELECT sqlite_version()`. [web:191]

Done: an hour-long run produces useful history without multiplying persistent sockets into fake new connections.

### Milestone C — traffic sampling (1–3 sessions; optional for first release)

Study: your local nettop manual; cumulative counters versus deltas; counter resets.

Build:

1. A separate nettop adapter with captured/sanitized fixtures.
2. Prefer a continuous sampling process if that yields stable counter semantics.
3. Associate process samples only when identity/time evidence is sufficient.
4. If counters are cumulative, compute deltas only within the same identity/counter epoch.
5. Treat process restarts, counter decreases and sleep/wake gaps as resets or missing data.
6. Never assign a whole process upload to one remote socket merely because it is visible.

Done: controlled dummy uploads produce a plausible process-level trend; unavailable bytes remain NULL, not zero.

### Milestone D — HTMX dashboard (2–3 sessions)

Study: Go templates and HTTP parsers; HTMX polling, targets and swaps.

Build:

- `/`: collector health, visible sockets, new destinations, recent findings.
- `/connections`: time/process/protocol filters and observed sessions.
- `/apps`: stable application summaries where identity supports them.
- `/processes/{instance}`: endpoints and process-level traffic timeline.
- `/findings`: explanations and acknowledgment.
- `/settings`: retention, pause/resume, optional enrichment.
- CSV/JSON export with explicit scope and time range.

Refresh read-only fragments every 5 seconds. Keep HTMX/CSS local, use `html/template` escaping, paginate history and exclude the monitor's own dashboard traffic by default.

Bind only to `127.0.0.1`. Validate Host/Origin where appropriate, protect mutating actions against CSRF, and do not enable wildcard CORS. A malicious webpage can target localhost: loopback binding alone is not a complete security boundary.

Done: while the collector continues running, you can investigate a process without a terminal.

### Milestone E — explainable anomalies (2–4 sessions plus observation time)

Begin with these rules, in this order:

1. New destination per application identity: informational; suppress initial learning-period floods.
2. Destination burst: count newly observed socket sessions/distinct IPs, not repeated snapshots. Mark as approximate because sampling is incomplete.
3. Upload spike: only after validated traffic sampling. Compare fixed-window totals against past comparable windows with an absolute minimum and enough history.
4. Known-domain match: only later when an actual domain signal exists. Do not classify original domains from PTR alone.

Proposed initial defaults: 48-hour learning period; 7-day rolling history for volume; 5-minute evaluation windows. Tune using your own observed workload, not a universal “safe” threshold.

Each finding contains:

- What changed and over which window.
- Application identity and confidence.
- Measured values and baseline sample count.
- Data source and coverage gaps.
- Why it could be normal: updates, sync, backups, CDN rotation, VPN change.
- Acknowledge/suppress action and expiration.

Do not claim exfiltration, maliciousness or browser fingerprint uniqueness from these rules. No machine learning until you have trustworthy measurements and labeled examples.

Done: a controlled new endpoint triggers one informational finding, repeated polls do not retrigger it, and a dummy upload generates an evidence-backed alert when volume support exists.

### Milestone F — background operation and privacy controls (1–2 sessions)

Study: Apple launchd guide and local `launchctl`/`launchd.plist` manuals.

Build:

1. Graceful shutdown with signal cancellation, queue draining and database close.
2. Per-user LaunchAgent under `~/Library/LaunchAgents` using absolute executable/config paths.
3. `RunAtLoad` and an intentional restart policy; do not self-daemonize.
4. App data under `~/Library/Application Support/Netwatch`; owner-only directory/file permissions.
5. Bounded logs, retention and disk-growth visibility.
6. Proposed retention: 7 days detailed observations, 30 days aggregates, configurable.
7. Pause, export, and clear-data behavior, including baselines, caches and alerts.

A LaunchAgent runs while the user is logged in, not as a boot-level system daemon. [web:192]

For backups, use a consistent SQLite backup/snapshot mechanism or stop and close the database before copying. Do not copy just the main database while WAL writes continue. Deletion is logical deletion, not guaranteed forensic erasure from SSDs or existing backups. [web:191]

Done: logout/login and sleep/wake do not corrupt state or create fake traffic spikes; collection can be stopped and its stored history cleared.

## 6. Optional enrichment — after the core works

Add cached PTR lookups through `net.Resolver.LookupAddr`, disabled by default or explicitly enabled. Use deadlines, rate limits, expiry and source labels. Lookups themselves generate DNS activity: exclude or mark monitor-generated traffic.

Keep these concepts separate:

- `remote_ip`: directly observed endpoint.
- `ptr_hostname`: reverse-DNS hint.
- `observed_domain`: actual DNS/browser signal, when available later.
- `domain_association_confidence`: how the domain was associated with a socket.

Do not send every destination to a third-party API. Prefer a locally stored ASN database if needed; record its license/version. Tracker lists should have source, version, update time, license and exact matching rules. Do not invent analytics/fingerprinting subcategories if the source only supplies a generic blocklist.

## 7. Reading queue — use each resource when its milestone needs it

### Required now

1. lsof manual — machine-readable fields and process/file structure:
   https://lsof.readthedocs.io/en/latest/manpage/
   Local commands: `man lsof`, `lsof -F '?'`.
2. nettop manual on your Mac — logging modes, process summaries and byte columns:
   `man nettop`.
   Background only; this online copy is old:
   https://www.manpagez.com/man/1/nettop/
3. Go subprocesses — cancellation and command lifecycle:
   https://pkg.go.dev/os/exec
4. Go address handling — IPv4/IPv6 parsing:
   https://pkg.go.dev/net/netip
5. Go SQL guide — transactions, query cancellation and pools:
   https://go.dev/doc/database/
6. SQLite Go driver — configuration and portability:
   https://pkg.go.dev/modernc.org/sqlite
7. SQLite WAL — concurrency, checkpoints and backups:
   https://www.sqlite.org/wal.html
8. Go HTML templates and HTTP server:
   https://pkg.go.dev/html/template
   https://pkg.go.dev/net/http
9. HTMX — polling and HTML partial responses:
   https://htmx.org/docs/
10. Apple launchd guide — agent lifecycle and foreground behavior:
    https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
    Also use current local `man launchctl` and `man launchd.plist`.
11. Wireshark TLS guide — understand encrypted-payload limitations; do not implement decryption for MVP:
    https://wiki.wireshark.org/TLS

### Later: Linux collector

12. ebpf-go official tutorial — Go loader, C kernel program and bpf2go:
    https://ebpf-go.dev/guides/getting-started/
13. cilium/ebpf repository — examples and attachment APIs:
    https://github.com/cilium/ebpf
14. Linux network namespace/proc documentation:
    https://www.man7.org/linux/man-pages/man5/proc_net.5.html
    Important correction: `/proc/<pid>/net/dev` describes that PID's network namespace, not its individual traffic. It is not a per-process byte counter. [web:194]

### Later: browser context

15. WebExtensions request events and permissions:
    https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest
16. uBlock Origin logger — inspect request context and filtering behavior:
    https://github.com/gorhill/uBlock/wiki/The-logger
    Use as a learning/reference tool; do not assume your extension can read uBlock's internal events. [web:127]

## 8. Roadmap after macOS MVP

### v0.2 — stabilize measurements

Run for a week. Improve parser fixtures, process identity, retention, false positives and collector-health reporting before adding more enrichment. Save representative sanitized fixtures when macOS output changes.

### v0.3 — Linux host collector

Keep models, storage, rules and dashboard; replace only the platform collector.

1. First implement socket snapshots via `/proc` or socket diagnostics, accounting for network namespaces, permissions and inode-to-process attribution.
2. Then add cilium/ebpf for event-driven process-aware connection visibility.
3. Start with connection attempts and results; a connect event is not proof of a successful established connection or payload transfer.
4. Add per-socket/process accounting separately. Plan UDP send paths, IPv6, retransmissions, process exits and lost events explicitly.
5. Keep privileged collection separate from the unprivileged web service. Determine capabilities from the chosen hooks/kernel rather than granting broad capabilities blindly.

Go owns the service; small eBPF programs are normally written in C and built with bpf2go. Linux avoids Apple's extension/signing model but still requires kernel compatibility, privileges and event-accounting work. XDP is not the default starting point for app-aware monitoring. [web:181][web:183]

You can prototype on a Linux VM while still on your Mac. It sees VM traffic, not native macOS traffic.

### v0.4 — actual DNS observations

Add resolver query-log ingestion or a deliberately configured local DNS source. Explain that browser DoH, OS caches and other resolvers can bypass it. Correlate domains to IPs with timestamps/TTL and ambiguity; resolver logs alone generally do not identify the originating process.

Keep DNS filtering optional: your product remains observe-only.

### v0.5 — browser extension

Add opt-in per-site browser request metadata: top-level site, third-party domains, resource type and timing. Match events using evidence and confidence, not just “a browser socket happened around the same time.” Browser HTTP/2 or HTTP/3 connections can serve multiple requests; the extension supplies context the socket collector cannot.

Do not collect page content, cookie values, tokens, request bodies or form inputs. Fingerprinting API instrumentation is a separate later experiment with false-positive/false-negative limitations.

### Collection split

`/usr/sbin/tcpdump -i pktap,en0 -n -k NPD -l` is the live feed. `lsof` is the socket inventory. `nettop` is not the collector. `gopacket` on `pktap,en0` is not either: on this Mac it returns raw IP with no process id, and it does not honor a short snaplen.

`tcpdump -k` prints the process name, PID, and direction. The name is not limited to 16 characters. It still misses a listener that receives nothing, and a socket that stays idle. With a VPN connected, the process on the captured packet is the VPN client. `lsof` is what shows the app that owns the socket.

`lsof` stays for `LISTEN`, idle sockets, the full command, the user, and TCP state. Run it on a slow cadence, on the order of a minute, not every few seconds.

`nettop -L 0` is the fallback if a `pktap` probe cannot produce a stable PID and 5-tuple, and the one-shot comparison that tells you how far the byte sums drift.

Endpoint Security and a Network Extension see connects without a packet capture, and they can block. Both need an Apple entitlement. They wait until this metadata loop is useful.

### Not scheduled: decrypting bodies

| Later tool | What it adds | Why it waits |
|---|---|---|
| TLS key log, for one app you started | Decrypted HTTP for clients that write session keys | Many apps never write the file. Do not store keys or bodies |
| mitmproxy, for one app that trusts your CA | HTTP bodies for proxied traffic | Pinning, QUIC, and non-HTTP protocols skip it. Requests can fail closed |
| Frida | Plaintext still inside that process | SIP and Hardened Runtime block it. A bad hook crashes the app. Hooks rot on each update |

`netstat` is not part of the stack. The macOS build has no process id on a socket. `gopacket` is for the `pktap` metadata header and the 5-tuple. It is not a TLS decoder.

### Optional — Grafana and VPS

HTMX remains the investigation UI. Add low-cardinality metrics for collector health, throughput and finding counts if Grafana becomes useful. Do not publish every PID/IP/domain as a Prometheus label.

Your VPS is not required for MVP. Later use it for a private authenticated multi-device aggregator or controlled test destination. A VPS cannot see your Mac's traffic merely because it exists. Never expose a recursive DNS resolver publicly; if using remote DNS, keep it behind a private VPN with access controls. A home resolver belongs on a reachable home host or router-supported service.

## 9. Release checklist

- [ ] Controlled TCP test maps to the correct process.
- [ ] IPv6, UDP without peer and listeners are represented honestly.
- [ ] Poll failures show gaps, not disconnections.
- [ ] Short-lived-connection limitations are visible in the UI.
- [ ] Process restarts/PID reuse do not merge unrelated instances.
- [ ] Counter resets cannot produce fabricated upload spikes.
- [ ] Destination alerts are deduplicated and suppressible.
- [ ] PTR labels are not presented as original request domains.
- [ ] Dashboard is loopback-only and mutations are protected.
- [ ] No payloads, secrets, browser history or default remote enrichment.
- [ ] Background startup, graceful shutdown and sleep/wake tested.
- [ ] Retention, pause/resume, export and clear-data tested.
- [ ] Source/coverage/confidence accompany each finding.

## 10. First coding session

```bash
mkdir netwatch && cd netwatch
git init
go mod init example.com/netwatch
go get modernc.org/sqlite
mkdir -p cmd/netwatch internal/collector/testdata internal/model
```

Build only `netwatch snapshot`: execute lsof, parse field output, print normalized JSON and test the parser. Do not build the web UI or anomaly engine until that observation is trustworthy.

First release goal: a background local monitor that can show historical process-to-IP activity and explain new/unusual behavior, without pretending to identify the contents of encrypted transfers.

