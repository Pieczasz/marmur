//go:build darwin

package darwin

import (
	"errors"

	"github.com/Pieczasz/marmur/internal/identity"
)

type Port struct{}

func (Port) Lookup(pid uint32) (identity.ProcessInfo, error) {
	return identity.ProcessInfo{}, errors.New("darwin.Port.Lookup: not implemented")
}
