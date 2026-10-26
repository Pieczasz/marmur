package capture

// PacketSummary is the per-run result of a packet sensor.
type PacketSummary struct {
	Emitted          int `json:"emitted"`
	NonIP            int `json:"non_ip"`
	Truncated        int `json:"truncated"`
	Unsupported      int `json:"unsupported"`
	OtherErrors      int `json:"other_errors"`
	Skipped          int `json:"skipped"`
	PacketsDropped   int `json:"packets_dropped"`
	PacketsIfDropped int `json:"packets_if_dropped"`
}

// SocketSummary is the per-run result of a socket sensor.
type SocketSummary struct {
	Emitted int `json:"emitted"`
}
