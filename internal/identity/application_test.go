package identity

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	zenPath        = "/Applications/Zen.app/Contents/MacOS/zen"
	zenSigner      = "9V5K9TP787:app.zen-browser.zen"
	protonPath     = "/Applications/Proton Mail.app/Contents/Frameworks/Proton Mail Helper.app/Contents/MacOS/Proton Mail Helper"
	protonSigner   = "2SB5Z68H26:ch.protonmail.desktop.helper"
	mdnsPath       = "/usr/sbin/mDNSResponder"
	mdnsSigner     = "com.apple.mDNSResponder"
	opencodePath   = "/Users/pieczasz/.opencode/bin/opencode"
	opencodeSigner = "5NZ4Q7NXJ4:opencode"
	cursorPath     = "/Users/pieczasz/Library/Application Support/Cursor/User/globalStorage/anysphere.cursor-agent-worker/agent-cli/.local/bin/cursor-agent"
)

func TestNewApplicationID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		path   string
		signer string
		want   ApplicationID
	}{
		{
			name:   "signed app with a team id",
			path:   zenPath,
			signer: zenSigner,
			want:   ApplicationID{Path: zenPath, Signer: zenSigner},
		},
		{
			name:   "path with spaces and parentheses",
			path:   protonPath,
			signer: protonSigner,
			want:   ApplicationID{Path: protonPath, Signer: protonSigner},
		},
		{
			name:   "apple platform binary without a team id",
			path:   mdnsPath,
			signer: mdnsSigner,
			want:   ApplicationID{Path: mdnsPath, Signer: mdnsSigner},
		},
		{
			name: "unsigned local binary",
			path: cursorPath,
			want: ApplicationID{Path: cursorPath},
		},
		{
			name:   "dot segment in the path",
			path:   "/Applications/Zen.app/Contents/MacOS/./zen",
			signer: zenSigner,
			want:   ApplicationID{Path: zenPath, Signer: zenSigner},
		},
		{
			name:   "duplicate separators in the path",
			path:   "/Applications//Zen.app/Contents/MacOS/zen",
			signer: zenSigner,
			want:   ApplicationID{Path: zenPath, Signer: zenSigner},
		},
		{
			name:   "trailing separator",
			path:   mdnsPath + "/",
			signer: mdnsSigner,
			want:   ApplicationID{Path: mdnsPath, Signer: mdnsSigner},
		},
		{
			name:   "signer whitespace is trimmed",
			path:   zenPath,
			signer: "  " + zenSigner + "  ",
			want:   ApplicationID{Path: zenPath, Signer: zenSigner},
		},
		{
			name:   "signer without a path is unattributed",
			signer: zenSigner,
			want:   Unattributed,
		},
		{
			name: "empty input",
			want: Unattributed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, tt.want, NewApplicationID(tt.path, tt.signer))
		})
	}
}

func TestApplicationIDIdentityRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		a     ApplicationID
		b     ApplicationID
		equal bool
	}{
		{
			name:  "same path and signer, whatever the process",
			a:     NewApplicationID(zenPath, zenSigner),
			b:     NewApplicationID(zenPath, zenSigner),
			equal: true,
		},
		{
			name:  "same short name, different path",
			a:     NewApplicationID("/opt/homebrew/bin/node", ""),
			b:     NewApplicationID("/usr/local/bin/node", ""),
			equal: false,
		},
		{
			name:  "same path, different signer",
			a:     NewApplicationID(zenPath, zenSigner),
			b:     NewApplicationID(zenPath, "AAAAAAAAAA:app.zen-browser.zen"),
			equal: false,
		},
		{
			name:  "same path, signed and unsigned",
			a:     NewApplicationID(opencodePath, opencodeSigner),
			b:     NewApplicationID(opencodePath, ""),
			equal: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.a == tt.b; got != tt.equal {
				t.Errorf("ids equal = %v, want %v (%v vs %v)", got, tt.equal, tt.a, tt.b)
			}
		})
	}
}

func TestApplicationIDDoesNotNormalizeCaseOrSymlinks(t *testing.T) {
	t.Parallel()

	require.NotEqual(t,
		NewApplicationID("/Applications/Zen.app/Contents/MacOS/zen", ""),
		NewApplicationID("/applications/zen.app/Contents/MacOS/zen", ""),
	)
	require.NotEqual(t,
		NewApplicationID("/tmp/app", ""),
		NewApplicationID("/private/tmp/app", ""),
	)
}

func TestUnattributedIsZero(t *testing.T) {
	t.Parallel()

	require.True(t, Unattributed.IsZero())
	require.False(t, NewApplicationID(zenPath, "").IsZero())
}

func ExampleNewApplicationID() {
	id := NewApplicationID("/Applications/Zen.app/Contents/MacOS/./zen", zenSigner)

	fmt.Println(id.Path)
	fmt.Println(id.Signer)
	fmt.Println(id.IsZero())

	// Output:
	// /Applications/Zen.app/Contents/MacOS/zen
	// 9V5K9TP787:app.zen-browser.zen
	// false
}

func FuzzNewApplicationID(f *testing.F) {
	f.Add(zenPath, zenSigner)
	f.Add("", "")
	f.Add("/usr/sbin//mDNSResponder/./", mdnsSigner)
	f.Add("relative/path", "signer")

	f.Fuzz(func(t *testing.T, path, signer string) {
		id := NewApplicationID(path, signer)
		if path == "" {
			if !id.IsZero() {
				t.Fatalf("empty path produced %+v", id)
			}
			return
		}
		if id.IsZero() {
			t.Fatalf("path %q produced a zero id", path)
		}
		if again := NewApplicationID(id.Path, id.Signer); again != id {
			t.Fatalf("not idempotent: %+v -> %+v", id, again)
		}
	})
}
