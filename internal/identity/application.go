package identity

import (
	"path/filepath"
	"strings"
)

type ApplicationID struct {
	Path   string
	Signer string
}

var Unattributed ApplicationID

func NewApplicationID(path, signer string) ApplicationID {
	if path == "" {
		return Unattributed
	}
	return ApplicationID{
		Path:   filepath.Clean(path),
		Signer: strings.TrimSpace(signer),
	}
}

func (id ApplicationID) IsZero() bool { return id == Unattributed }
