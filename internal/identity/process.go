package identity

import (
	"errors"
	"time"
)

var (
	ErrProcessGone = errors.New("the process with this PID doesn't exist anymore")
	ErrPermission  = errors.New("kernel refused a lookup")
)

type ProcessKey struct {
	PID       uint32
	StartTime time.Time
}

type ProcessRef struct {
	PID          uint32
	EffectivePID uint32
	Delegated    bool
}

type ProcessInfo struct {
	Key       ProcessKey
	Name      string
	Path      string
	Signer    string
	ParentPID uint32
}

func NewProcessKey(pid uint32, start time.Time) ProcessKey {
	return ProcessKey{PID: pid, StartTime: start.Round(0).UTC()}
}
