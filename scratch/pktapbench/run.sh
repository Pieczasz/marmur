#!/bin/sh
# Builds the benchmark as you, then runs it as root.
# parseTcpdumpLine is unexported, so the collector files are copied in at build time
# (always the current version, never committed).
set -eu
cd "$(dirname "$0")"

for f in tcpdump lsof; do
	sed 's/^package collector$/package main/' "../../internal/collector/$f.go" > "zz_collector_$f.go"
done
go build -o pktapbench .

sudo ./pktapbench "$@"
