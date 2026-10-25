// Package capture contains the observations shared by every sensor.
package capture

import (
	"net/netip"
	"time"
)

type Direction string

const (
	DirectionIn  Direction = "in"
	DirectionOut Direction = "out"
)

type Protocol string

const (
	TCP    Protocol = "TCP"
	UDP    Protocol = "UDP"
	ICMP   Protocol = "ICMP"
	ICMPv6 Protocol = "ICMPV6"
	ESP    Protocol = "ESP"
)

type TCPState string

const (
	StateEstablished TCPState = "ESTABLISHED"
	StateListen      TCPState = "LISTEN"
	StateCloseWait   TCPState = "CLOSE_WAIT"
	StateTimeWait    TCPState = "TIME_WAIT"
	StateSynSent     TCPState = "SYN_SENT"
	StateNone        TCPState = "" // For UDP / ICMP
)

type PacketEvent struct {
	ObservedAt time.Time      `json:"observed_at"` // UTC
	Src        netip.AddrPort `json:"src"`         // port 0 for ICMP/ESP
	Dst        netip.AddrPort `json:"dst"`         // port 0 for ICMP/ESP

	Interface        string    `json:"interface"` // "utun6", "en0", "" if absent
	Process          string    `json:"process"`
	ProcessUUID      string    `json:"process_uuid"`
	EffectiveProcess string    `json:"effective_process"` // PKTAP specific
	EffectiveUUID    string    `json:"effective_uuid"`    // PKTAP specific
	Direction        Direction `json:"direction"`
	Protocol         Protocol  `json:"protocol"`

	Length       int    `json:"length"`
	PID          uint32 `json:"pid"`
	EffectivePID uint32 `json:"effective_pid"` // PKTAP specific
	FlowID       uint32 `json:"flow_id"`       // PKTAP specific
	Delegated    bool   `json:"delegated"`     // PKTAP specific
}

type SocketEndpoint struct {
	Addr       netip.Addr `json:"addr"`
	Port       uint16     `json:"port"`
	IsWildcard bool       `json:"is_wildcard"`
}

type SocketEvent struct {
	ObservedAt time.Time `json:"observed_at"`

	Local  SocketEndpoint  `json:"local"`
	Remote *SocketEndpoint `json:"remote,omitempty"`

	Command  string   `json:"command"`
	User     string   `json:"user"`
	Protocol Protocol `json:"protocol"`
	TCPState TCPState `json:"tcp_state"`

	PID            uint32 `json:"pid"`
	FileDescriptor uint32 `json:"file_descriptor"`
	AccessMode     string `json:"access_mode"`
}

func (e *SocketEvent) IsIPv4() bool {
	return e.Local.Addr.Is4() || (e.Remote != nil && e.Remote.Addr.Is4())
}

func (e *SocketEvent) IsIPv6() bool {
	return e.Local.Addr.Is6() || (e.Remote != nil && e.Remote.Addr.Is6())
}
