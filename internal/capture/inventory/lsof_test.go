package inventory

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Pieczasz/marmur/internal/capture"
)

var testNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

func TestParseLsofStream(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected []capture.SocketEvent
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "zen",
					PID:            59292,
					User:           "pieczasz",
					FileDescriptor: 115,
					AccessMode:     "u",
					Protocol:       capture.TCP,
					TCPState:       capture.StateEstablished,
					Local: capture.SocketEndpoint{
						Addr:       netip.MustParseAddr("10.2.0.2"),
						Port:       50867,
						IsWildcard: false,
					},
					Remote: &capture.SocketEndpoint{
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "rapportd",
					PID:            941,
					User:           "pieczasz",
					FileDescriptor: 11,
					AccessMode:     "u",
					Protocol:       capture.TCP,
					TCPState:       capture.StateListen,
					Local: capture.SocketEndpoint{
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "identityservicesd",
					PID:            956,
					User:           "pieczasz",
					FileDescriptor: 13,
					AccessMode:     "u",
					Protocol:       capture.UDP,
					TCPState:       capture.StateNone,
					Local: capture.SocketEndpoint{
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "node",
					PID:            1234,
					User:           "root",
					FileDescriptor: 4,
					AccessMode:     "w",
					Protocol:       capture.TCP,
					TCPState:       capture.StateEstablished,
					Local: capture.SocketEndpoint{
						Addr:       netip.MustParseAddr("::1"),
						Port:       3000,
						IsWildcard: false,
					},
					Remote: &capture.SocketEndpoint{
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "daemon",
					PID:            500,
					User:           "user",
					FileDescriptor: 5,
					AccessMode:     "u",
					Protocol:       capture.TCP,
					TCPState:       capture.StateListen,
					Local: capture.SocketEndpoint{
						Addr:       netip.MustParseAddr("127.0.0.1"),
						Port:       8080,
						IsWildcard: false,
					},
					Remote: nil,
				},
				{
					ObservedAt:     testNow,
					Command:        "daemon",
					PID:            500,
					User:           "user",
					FileDescriptor: 6,
					AccessMode:     "u",
					Protocol:       capture.TCP,
					TCPState:       capture.StateEstablished,
					Local: capture.SocketEndpoint{
						Addr:       netip.MustParseAddr("192.168.1.10"),
						Port:       52000,
						IsWildcard: false,
					},
					Remote: &capture.SocketEndpoint{
						Addr:       netip.MustParseAddr("1.1.1.1"),
						Port:       53,
						IsWildcard: false,
					},
				},
				{
					ObservedAt:     testNow,
					Command:        "other",
					PID:            600,
					User:           "user",
					FileDescriptor: 3,
					AccessMode:     "r",
					Protocol:       capture.UDP,
					TCPState:       capture.StateNone,
					Local: capture.SocketEndpoint{
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "badapp",
					PID:            777,
					User:           "user",
					FileDescriptor: 10,
					AccessMode:     "u",
					Protocol:       capture.TCP,
					TCPState:       capture.StateNone,
					Local: capture.SocketEndpoint{
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "curl",
					PID:            700,
					User:           "pieczasz",
					FileDescriptor: 20,
					AccessMode:     "u",
					Protocol:       capture.TCP,
					TCPState:       capture.StateCloseWait,
					Local: capture.SocketEndpoint{
						Addr:       netip.MustParseAddr("10.2.0.2"),
						Port:       51001,
						IsWildcard: false,
					},
					Remote: &capture.SocketEndpoint{
						Addr:       netip.MustParseAddr("66.203.125.13"),
						Port:       443,
						IsWildcard: false,
					},
				},
				{
					ObservedAt:     testNow,
					Command:        "curl",
					PID:            700,
					User:           "pieczasz",
					FileDescriptor: 21,
					AccessMode:     "u",
					Protocol:       capture.TCP,
					TCPState:       capture.StateTimeWait,
					Local: capture.SocketEndpoint{
						Addr:       netip.MustParseAddr("10.2.0.2"),
						Port:       51002,
						IsWildcard: false,
					},
					Remote: &capture.SocketEndpoint{
						Addr:       netip.MustParseAddr("142.250.180.206"),
						Port:       443,
						IsWildcard: false,
					},
				},
				{
					ObservedAt:     testNow,
					Command:        "curl",
					PID:            700,
					User:           "pieczasz",
					FileDescriptor: 22,
					AccessMode:     "u",
					Protocol:       capture.TCP,
					TCPState:       capture.StateSynSent,
					Local: capture.SocketEndpoint{
						Addr:       netip.MustParseAddr("10.2.0.2"),
						Port:       51003,
						IsWildcard: false,
					},
					Remote: &capture.SocketEndpoint{
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "com.docker.backend",
					PID:            63116,
					User:           "pieczasz",
					FileDescriptor: 98,
					AccessMode:     "u",
					Protocol:       capture.ICMP,
					TCPState:       capture.StateNone,
					Local: capture.SocketEndpoint{
						Port:       0,
						IsWildcard: true,
					},
					Remote: nil,
				},
				{
					ObservedAt:     testNow,
					Command:        "com.docker.backend",
					PID:            63116,
					User:           "pieczasz",
					FileDescriptor: 99,
					AccessMode:     "u",
					Protocol:       capture.ICMPv6,
					TCPState:       capture.StateNone,
					Local: capture.SocketEndpoint{
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "Discord Helper (Renderer)",
					PID:            81623,
					User:           "501",
					FileDescriptor: 23,
					Protocol:       capture.UDP,
					TCPState:       capture.StateNone,
					Local: capture.SocketEndpoint{
						Addr: netip.MustParseAddr("10.2.0.2"),
						Port: 64603,
					},
					Remote: &capture.SocketEndpoint{
						Addr: netip.MustParseAddr("162.159.135.232"),
						Port: 443,
					},
				},
				{
					ObservedAt:     testNow,
					Command:        "Discord Helper (Renderer)",
					PID:            81623,
					User:           "501",
					FileDescriptor: 30,
					Protocol:       capture.TCP,
					TCPState:       capture.StateEstablished,
					Local: capture.SocketEndpoint{
						Addr: netip.MustParseAddr("10.2.0.2"),
						Port: 53053,
					},
					Remote: &capture.SocketEndpoint{
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "full-line-inference",
					PID:            86101,
					User:           "501",
					FileDescriptor: 9,
					Protocol:       capture.TCP,
					TCPState:       capture.StateListen,
					Local: capture.SocketEndpoint{
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
			expected: []capture.SocketEvent{
				{
					ObservedAt:     testNow,
					Command:        "com.apple.WebKit.Networking",
					PID:            400,
					User:           "501",
					FileDescriptor: 8,
					Protocol:       capture.TCP,
					TCPState:       "CLOSED",
					Local: capture.SocketEndpoint{
						Addr: netip.MustParseAddr("10.2.0.2"),
						Port: 52282,
					},
					Remote: &capture.SocketEndpoint{
						Addr: netip.MustParseAddr("35.186.224.24"),
						Port: 443,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := newLSOFParser(testNow)
			lines := strings.SplitSeq(tt.input, "\n")
			for line := range lines {
				if len(line) < 2 {
					continue
				}
				p.parseFlag(line[0], line[1:])
			}

			require.Equal(t, tt.expected, p.finish())
		})
	}
}

func FuzzParseLsofStream(f *testing.F) {
	seeds := []string{
		"",
		"p59292\nczen\nupieczasz\nf115u\nPTCP\nTST=ESTABLISHED\nn10.2.0.2:50867->66.203.125.13:443",
		"p941\ncrapportd\nupieczasz\nf11u\nPTCP\nTST=LISTEN\nn*:50265",
		"p956\ncidentityservicesd\nupieczasz\nf13u\nPUDP\nn*:*",
		"p1\nf\nf999999999999999999999\nPX\nn[::1]:1->[::1]:2",
		"p\f1\nf-1\nPX\nn1.2.3.4:99999->:",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		p := newLSOFParser(testNow)

		lines := strings.SplitSeq(input, "\n")
		for line := range lines {
			if len(line) < 2 {
				continue
			}
			p.parseFlag(line[0], line[1:])
		}

		for _, ev := range p.finish() {
			switch ev.Protocol {
			case capture.TCP, capture.UDP, capture.ICMP, capture.ICMPv6, capture.ESP:
			default:
				t.Errorf("unexpected protocol %q from %q", ev.Protocol, input)
			}
			if !ev.ObservedAt.Equal(testNow) {
				t.Errorf("event stamped with %v, want %v", ev.ObservedAt, testNow)
			}
		}
	})
}
