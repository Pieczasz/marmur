//go:build darwin

package darwin

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/Pieczasz/marmur/internal/identity"
)

func TestLookupSelf(t *testing.T) {
	t.Parallel()

	pid := uint32(os.Getpid())
	info, err := Port{}.Lookup(pid)
	require.NoError(t, err)

	exe, err := os.Executable()
	require.NoError(t, err)
	exe, err = filepath.EvalSymlinks(exe)
	require.NoError(t, err)

	require.Equal(t, pid, info.Key.PID)
	require.Equal(t, exe, info.Path)
	require.False(t, info.Key.StartTime.After(time.Now()))
	require.Equal(t, uint32(os.Getppid()), info.ParentPID)
	require.NotEmpty(t, info.Name)
}

func TestLookupMissing(t *testing.T) {
	t.Parallel()

	_, err := Port{}.Lookup(999999) // above PID_MAX on macOS
	require.ErrorIs(t, err, identity.ErrProcessGone)
}

// Set MARMUR_IDENTITY_PIDS=487,10196 to inspect the live processes by hand.
func TestLookupLivePIDs(t *testing.T) {
	raw := os.Getenv("MARMUR_IDENTITY_PIDS")
	if raw == "" {
		t.Skip("set MARMUR_IDENTITY_PIDS=pid,pid to inspect live processes")
	}

	t.Parallel()

	for _, field := range strings.Split(raw, ",") {
		parsed, err := strconv.ParseUint(strings.TrimSpace(field), 10, 32)
		require.NoError(t, err)
		pid := uint32(parsed)

		t.Run(strconv.FormatUint(parsed, 10), func(t *testing.T) {
			t.Parallel()

			info, err := Port{}.Lookup(pid)
			require.NoError(t, err)
			t.Logf("path=%q name=%q ppid=%d start=%s signer=%q",
				info.Path, info.Name, info.ParentPID, info.Key.StartTime.Format(time.RFC3339Nano), info.Signer)
		})
	}
}
