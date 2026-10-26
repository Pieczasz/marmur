# marmur

A local, privacy-first network monitor for your own Mac.

It answers one question: **which applications talk to whom, how much, and what is new or unusual?** Every answer comes
with evidence. The monitor itself never becomes a second surveillance dataset.

## What it does

The monitor is built in three layers. Only the first is always on.

| Layer       | What it does                                                                                                                                                        | Default                           |
|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------|
| **Observe** | Per-app flows (who, where, how much, when), destination names from DNS and TLS, owners and tracker/telemetry labels from downloaded lists, and explainable findings | always on, metadata only          |
| **Inspect** | Decrypt one app's traffic for a short session and check whether *your* personal data appears in its requests, using planted canary values                           | off; one app at a time            |
| **Enforce** | Suggest blocks for what you found. A local DNS resolver, LuLu or mitmproxy applies them after you approve                                                           | off; nothing blocks automatically |

## What it never does

- Store packet payloads or request bodies.
- Send any destination, domain or hash to a third party; every list it uses is downloaded and used locally.
- Watch anyone else's devices or network.
- Reduce findings to a single "malicious %" score. Each finding is labeled privacy, security, unusual or policy, with
  its evidence and possible benign explanations.

## How it works

```text
kernel PKTAP ──► capture helper (root, tiny) ──► monitor (your user) ──► SQLite ──► dashboard
 app + PID         decodes headers, DNS, SNI       identity · flows ·                127.0.0.1
 per packet        drops packet bytes               names · labels · findings
```

- **Capture.** macOS tags every packet with its process (PKTAP). The monitor reads it in-process with [
  `gopacket`](https://github.com/gopacket/gopacket) and turns it into one-minute flows per application. `lsof` fills in
  listeners and idle sockets.
- **Attribution.** Traffic a system daemon sends for an app (e.g. DNS lookups) is credited to that app. VPN traffic is
  counted once.
- **Labels.** Owners, ASNs and tracker/telemetry categories come from downloaded datasets (iptoasn, HaGeZi, DuckDuckGo
  Tracker Radar, Spamhaus), each with its source and license.
- **Findings.** Explainable rules (new destination, known tracker, upload spike, …) over each app's own baseline. ML
  only later, and only locally.
- **Interface.** A small web dashboard on 127.0.0.1, written with Go templates and HTMX.

Written in Go. macOS first; Linux (eBPF) later behind the same model.

## Building and testing

Requirements:

- macOS with Apple's system libpcap
- Go 1.27
- cgo (for live capture)
- root only for live capture

```bash
go test ./...
```

```bash
go test ./internal/capture/darwin -run '^$' -fuzz FuzzDecodePktap -fuzztime 30s
```

Tests never need root or live traffic. The collector benchmark in `scratch/pktapbench` does; it asks for your password
and uses loopback traffic only:

```bash
./scratch/pktapbench/run.sh
```

## Status

Early development. The parsers and the collector benchmark are done; live capture and storage are being built now.

## License

MIT, see [LICENSE](LICENSE).
