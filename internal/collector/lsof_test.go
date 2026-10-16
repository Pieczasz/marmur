package collector

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseLsofStream(t *testing.T) {
	fixedTime := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		input    string
		expected []SocketEvent
	}{
		{
			name: "Established IPv4 TCP Connection",
			input: strings.Join([]string{
				"p59292",
				"czen",
				"upieczasz",
				"f115u",
				"PTCP",
				"TST=ESTABLISHED",
				"n10.2.0.2:50867->66.203.125.13:443",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "zen",
					PID:            59292,
					User:           "pieczasz",
					FileDescriptor: 115,
					AccessMode:     'u',
					Protocol:       TCP,
					TCPState:       StateEstablished,
					Local: SocketEndpoint{
						Addr:       netip.MustParseAddr("10.2.0.2"),
						Port:       50867,
						IsWildcard: false,
					},
					Remote: &SocketEndpoint{
						Addr:       netip.MustParseAddr("66.203.125.13"),
						Port:       443,
						IsWildcard: false,
					},
				},
			},
		},
		{
			name: "Listening TCP Socket on Wildcard",
			input: strings.Join([]string{
				"p941",
				"crapportd",
				"upieczasz",
				"f11u",
				"PTCP",
				"TST=LISTEN",
				"n*:50265",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "rapportd",
					PID:            941,
					User:           "pieczasz",
					FileDescriptor: 11,
					AccessMode:     'u',
					Protocol:       TCP,
					TCPState:       StateListen,
					Local: SocketEndpoint{
						Port:       50265,
						IsWildcard: true,
					},
					Remote: nil,
				},
			},
		},
		{
			name: "UDP Wildcard Binding",
			input: strings.Join([]string{
				"p956",
				"cidentityservicesd",
				"upieczasz",
				"f13u",
				"PUDP",
				"n*:*",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "identityservicesd",
					PID:            956,
					User:           "pieczasz",
					FileDescriptor: 13,
					AccessMode:     'u',
					Protocol:       UDP,
					TCPState:       StateNone,
					Local: SocketEndpoint{
						Port:       0,
						IsWildcard: true,
					},
					Remote: nil,
				},
			},
		},
		{
			name: "IPv6 Loopback Connection with brackets",
			input: strings.Join([]string{
				"p1234",
				"cnode",
				"uroot",
				"f4w",
				"PTCP",
				"TST=ESTABLISHED",
				"n[::1]:3000->[::1]:54321",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "node",
					PID:            1234,
					User:           "root",
					FileDescriptor: 4,
					AccessMode:     'w',
					Protocol:       TCP,
					TCPState:       StateEstablished,
					Local: SocketEndpoint{
						Addr:       netip.MustParseAddr("::1"),
						Port:       3000,
						IsWildcard: false,
					},
					Remote: &SocketEndpoint{
						Addr:       netip.MustParseAddr("::1"),
						Port:       54321,
						IsWildcard: false,
					},
				},
			},
		},
		{
			name: "Multiple Sockets Under Single Process and Multiple Processes",
			input: strings.Join([]string{
				"p500",
				"cdaemon",
				"uuser",
				"f5u",
				"PTCP",
				"TST=LISTEN",
				"n127.0.0.1:8080",
				"f6u",
				"PTCP",
				"TST=ESTABLISHED",
				"n192.168.1.10:52000->1.1.1.1:53",
				"p600",
				"cother",
				"uuser",
				"f3r",
				"PUDP",
				"n*:12345",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "daemon",
					PID:            500,
					User:           "user",
					FileDescriptor: 5,
					AccessMode:     'u',
					Protocol:       TCP,
					TCPState:       StateListen,
					Local: SocketEndpoint{
						Addr:       netip.MustParseAddr("127.0.0.1"),
						Port:       8080,
						IsWildcard: false,
					},
					Remote: nil,
				},
				{
					ObservedAt:     fixedTime,
					Command:        "daemon",
					PID:            500,
					User:           "user",
					FileDescriptor: 6,
					AccessMode:     'u',
					Protocol:       TCP,
					TCPState:       StateEstablished,
					Local: SocketEndpoint{
						Addr:       netip.MustParseAddr("192.168.1.10"),
						Port:       52000,
						IsWildcard: false,
					},
					Remote: &SocketEndpoint{
						Addr:       netip.MustParseAddr("1.1.1.1"),
						Port:       53,
						IsWildcard: false,
					},
				},
				{
					ObservedAt:     fixedTime,
					Command:        "other",
					PID:            600,
					User:           "user",
					FileDescriptor: 3,
					AccessMode:     'r',
					Protocol:       UDP,
					TCPState:       StateNone,
					Local: SocketEndpoint{
						Port:       12345,
						IsWildcard: true,
					},
					Remote: nil,
				},
			},
		},
		{
			name: "parses Empty Lines and Unrelated Tags Gracefully",
			input: strings.Join([]string{
				"",
				"p777",
				"xUnknownTag",
				"cbadapp",
				"uuser",
				"f", // malformed bare tag
				"f10u",
				"PTCP",
				"n*:443",
				"",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "badapp",
					PID:            777,
					User:           "user",
					FileDescriptor: 10,
					AccessMode:     'u',
					Protocol:       TCP,
					TCPState:       StateNone,
					Local: SocketEndpoint{
						Port:       443,
						IsWildcard: true,
					},
					Remote: nil,
				},
			},
		},
		{
			name: "TCP CLOSE_WAIT TIME_WAIT and SYN_SENT",
			input: strings.Join([]string{
				"p700",
				"ccurl",
				"upieczasz",
				"f20u",
				"PTCP",
				"n10.2.0.2:51001->66.203.125.13:443",
				"TST=CLOSE_WAIT",
				"TQR=0",
				"TQS=0",
				"f21u",
				"PTCP",
				"n10.2.0.2:51002->142.250.180.206:443",
				"TST=TIME_WAIT",
				"TQR=0",
				"TQS=0",
				"f22u",
				"PTCP",
				"n10.2.0.2:51003->93.184.216.34:443",
				"TST=SYN_SENT",
				"TQR=0",
				"TQS=128",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "curl",
					PID:            700,
					User:           "pieczasz",
					FileDescriptor: 20,
					AccessMode:     'u',
					Protocol:       TCP,
					TCPState:       StateCloseWait,
					Local: SocketEndpoint{
						Addr:       netip.MustParseAddr("10.2.0.2"),
						Port:       51001,
						IsWildcard: false,
					},
					Remote: &SocketEndpoint{
						Addr:       netip.MustParseAddr("66.203.125.13"),
						Port:       443,
						IsWildcard: false,
					},
				},
				{
					ObservedAt:     fixedTime,
					Command:        "curl",
					PID:            700,
					User:           "pieczasz",
					FileDescriptor: 21,
					AccessMode:     'u',
					Protocol:       TCP,
					TCPState:       StateTimeWait,
					Local: SocketEndpoint{
						Addr:       netip.MustParseAddr("10.2.0.2"),
						Port:       51002,
						IsWildcard: false,
					},
					Remote: &SocketEndpoint{
						Addr:       netip.MustParseAddr("142.250.180.206"),
						Port:       443,
						IsWildcard: false,
					},
				},
				{
					ObservedAt:     fixedTime,
					Command:        "curl",
					PID:            700,
					User:           "pieczasz",
					FileDescriptor: 22,
					AccessMode:     'u',
					Protocol:       TCP,
					TCPState:       StateSynSent,
					Local: SocketEndpoint{
						Addr:       netip.MustParseAddr("10.2.0.2"),
						Port:       51003,
						IsWildcard: false,
					},
					Remote: &SocketEndpoint{
						Addr:       netip.MustParseAddr("93.184.216.34"),
						Port:       443,
						IsWildcard: false,
					},
				},
			},
		},
		{
			name: "ICMP and ICMPv6 wildcard sockets",
			input: strings.Join([]string{
				"p63116",
				"ccom.docker.backend",
				"upieczasz",
				"f98u",
				"PICMP",
				"n*:*",
				"f99u",
				"PICMPV6",
				"n*:*",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "com.docker.backend",
					PID:            63116,
					User:           "pieczasz",
					FileDescriptor: 98,
					AccessMode:     'u',
					Protocol:       ICMP,
					TCPState:       StateNone,
					Local: SocketEndpoint{
						Port:       0,
						IsWildcard: true,
					},
					Remote: nil,
				},
				{
					ObservedAt:     fixedTime,
					Command:        "com.docker.backend",
					PID:            63116,
					User:           "pieczasz",
					FileDescriptor: 99,
					AccessMode:     'u',
					Protocol:       ICMPv6,
					TCPState:       StateNone,
					Local: SocketEndpoint{
						Port:       0,
						IsWildcard: true,
					},
					Remote: nil,
				},
			},
		},
		{
			name: "Bare FD numeric UID spaced command and UDP with remote",
			input: strings.Join([]string{
				"p81623",
				"cDiscord Helper (Renderer)",
				"u501",
				"f23",
				"PUDP",
				"n10.2.0.2:64603->162.159.135.232:443",
				"f30",
				"PTCP",
				"n10.2.0.2:53053->162.159.130.232:443",
				"TST=ESTABLISHED",
				"TQR=0",
				"TQS=0",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "Discord Helper (Renderer)",
					PID:            81623,
					User:           "501",
					FileDescriptor: 23,
					Protocol:       UDP,
					TCPState:       StateNone,
					Local: SocketEndpoint{
						Addr: netip.MustParseAddr("10.2.0.2"),
						Port: 64603,
					},
					Remote: &SocketEndpoint{
						Addr: netip.MustParseAddr("162.159.135.232"),
						Port: 443,
					},
				},
				{
					ObservedAt:     fixedTime,
					Command:        "Discord Helper (Renderer)",
					PID:            81623,
					User:           "501",
					FileDescriptor: 30,
					Protocol:       TCP,
					TCPState:       StateEstablished,
					Local: SocketEndpoint{
						Addr: netip.MustParseAddr("10.2.0.2"),
						Port: 53053,
					},
					Remote: &SocketEndpoint{
						Addr: netip.MustParseAddr("162.159.130.232"),
						Port: 443,
					},
				},
			},
		},
		{
			name: "IPv6 listen on a bracketed address",
			input: strings.Join([]string{
				"p86101",
				"cfull-line-inference",
				"u501",
				"f9",
				"PTCP",
				"n[::1]:52845",
				"TST=LISTEN",
				"TQR=0",
				"TQS=0",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "full-line-inference",
					PID:            86101,
					User:           "501",
					FileDescriptor: 9,
					Protocol:       TCP,
					TCPState:       StateListen,
					Local: SocketEndpoint{
						Addr: netip.MustParseAddr("::1"),
						Port: 52845,
					},
					Remote: nil,
				},
			},
		},
		{
			name: "TCP CLOSED state is kept",
			input: strings.Join([]string{
				"p400",
				"ccom.apple.WebKit.Networking",
				"u501",
				"f8",
				"PTCP",
				"n10.2.0.2:52282->35.186.224.24:443",
				"TST=CLOSED",
				"TQR=0",
				"TQS=0",
			}, "\n"),
			expected: []SocketEvent{
				{
					ObservedAt:     fixedTime,
					Command:        "com.apple.WebKit.Networking",
					PID:            400,
					User:           "501",
					FileDescriptor: 8,
					Protocol:       TCP,
					TCPState:       "CLOSED",
					Local: SocketEndpoint{
						Addr: netip.MustParseAddr("10.2.0.2"),
						Port: 52282,
					},
					Remote: &SocketEndpoint{
						Addr: netip.MustParseAddr("35.186.224.24"),
						Port: 443,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := newLSOFParser(fixedTime)
			lines := strings.Split(tt.input, "\n")
			for _, line := range lines {
				if len(line) < 2 {
					continue
				}
				p.parseFlag(line[0], line[1:])
			}
			actual := p.finish()

			if len(actual) != len(tt.expected) {
				t.Fatalf("expected %d events, got %d", len(tt.expected), len(actual))
			}

			for i := range actual {
				assertSocketEvent(t, i, tt.expected[i], actual[i])
			}
		})
	}
}

func assertSocketEvent(t *testing.T, idx int, exp, act SocketEvent) {
	t.Helper()

	if act.PID != exp.PID {
		t.Errorf("[%d] PID mismatch: expected %d, got %d", idx, exp.PID, act.PID)
	}
	if act.Command != exp.Command {
		t.Errorf("[%d] Command mismatch: expected %q, got %q", idx, exp.Command, act.Command)
	}
	if act.User != exp.User {
		t.Errorf("[%d] User mismatch: expected %q, got %q", idx, exp.User, act.User)
	}
	if act.FileDescriptor != exp.FileDescriptor {
		t.Errorf("[%d] FD mismatch: expected %d, got %d", idx, exp.FileDescriptor, act.FileDescriptor)
	}
	if act.AccessMode != exp.AccessMode {
		t.Errorf("[%d] AccessMode mismatch: expected %q, got %q", idx, exp.AccessMode, act.AccessMode)
	}
	if act.Protocol != exp.Protocol {
		t.Errorf("[%d] Protocol mismatch: expected %q, got %q", idx, exp.Protocol, act.Protocol)
	}
	if act.TCPState != exp.TCPState {
		t.Errorf("[%d] TCPState mismatch: expected %q, got %q", idx, exp.TCPState, act.TCPState)
	}

	assertEndpoint(t, idx, "Local", exp.Local, act.Local)

	if (exp.Remote == nil) != (act.Remote == nil) {
		t.Fatalf("[%d] Remote presence mismatch: expected nil=%v, got nil=%v", idx, exp.Remote == nil, act.Remote == nil)
	}
	if exp.Remote != nil && act.Remote != nil {
		assertEndpoint(t, idx, "Remote", *exp.Remote, *act.Remote)
	}
}

func assertEndpoint(t *testing.T, idx int, side string, exp, act SocketEndpoint) {
	t.Helper()

	if exp.IsWildcard != act.IsWildcard {
		t.Errorf("[%d] %s IsWildcard mismatch: expected %v, got %v", idx, side, exp.IsWildcard, act.IsWildcard)
	}
	if exp.Port != act.Port {
		t.Errorf("[%d] %s Port mismatch: expected %d, got %d", idx, side, exp.Port, act.Port)
	}
	if exp.Addr != act.Addr {
		t.Errorf("[%d] %s Addr mismatch: expected %s, got %s", idx, side, exp.Addr, act.Addr)
	}
}
