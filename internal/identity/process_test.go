package identity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewProcessKeyNormalizes(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 26, 9, 41, 53, 123456000, time.Local)
	require.Equal(t, ProcessKey{PID: 487, StartTime: start.UTC()}, NewProcessKey(487, start))

	now := time.Now() // carries a monotonic reading
	assert.Equal(t, NewProcessKey(1, now), NewProcessKey(1, now.UTC()))
}

func TestNewProcessKeyDistinguishesInstances(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 26, 9, 41, 53, 0, time.UTC)

	tests := []struct {
		name string
		a    ProcessKey
		b    ProcessKey
		want bool
	}{
		{
			name: "same pid and start",
			a:    NewProcessKey(10196, start),
			b:    NewProcessKey(10196, start),
			want: true,
		},
		{
			name: "same pid, different start",
			a:    NewProcessKey(10196, start),
			b:    NewProcessKey(10196, start.Add(time.Nanosecond)),
			want: false,
		},
		{
			name: "different pid, same start",
			a:    NewProcessKey(10196, start),
			b:    NewProcessKey(10197, start),
			want: false,
		},
		{
			name: "same pid reused a day later",
			a:    NewProcessKey(487, start),
			b:    NewProcessKey(487, start.Add(24*time.Hour)),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := tt.a == tt.b; got != tt.want {
				t.Errorf("keys equal = %v, want %v (%v vs %v)", got, tt.want, tt.a, tt.b)
			}
		})
	}
}
