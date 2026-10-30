package identity

import (
	"errors"
	"sync"
	"time"
)

const cacheTTL = 30 * time.Second

type ProcessInfoPort interface {
	Lookup(pid uint32) (ProcessInfo, error)
}

type cachedApp struct {
	app     ApplicationID
	expires time.Time
}

type Resolver struct {
	port ProcessInfoPort

	mu    sync.Mutex
	cache map[uint32]cachedApp
}

func NewResolver(port ProcessInfoPort) *Resolver {
	return &Resolver{port: port, cache: make(map[uint32]cachedApp)}
}

func (r *Resolver) Resolve(ref ProcessRef, at time.Time) ApplicationID {
	if ref.PID == 0 {
		return Unattributed
	}
	if ref.Delegated && ref.EffectivePID != 0 && ref.EffectivePID != ref.PID {
		if app := r.resolvePID(ref.EffectivePID, at); !app.IsZero() {
			return app
		}
	}
	return r.resolvePID(ref.PID, at)
}

func (r *Resolver) resolvePID(pid uint32, at time.Time) ApplicationID {
	if app, ok := r.cached(pid, at); ok {
		return app
	}

	info, err := r.port.Lookup(pid)
	if err != nil {
		if errors.Is(err, ErrProcessGone) {
			return r.afterExit(pid, at)
		}
		return Unattributed
	}

	if info.Key.PID != pid || info.Key.StartTime.After(at) {
		return Unattributed
	}

	app := NewApplicationID(info.Path, info.Signer)
	r.store(pid, app, at)
	return app
}

func (r *Resolver) cached(pid uint32, at time.Time) (ApplicationID, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.cache[pid]
	if !ok || !at.Before(entry.expires) {
		return Unattributed, false
	}
	return entry.app, true
}

func (r *Resolver) afterExit(pid uint32, at time.Time) ApplicationID {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry := r.cache[pid]
	entry.expires = at.Add(cacheTTL)
	r.cache[pid] = entry
	return entry.app
}

func (r *Resolver) store(pid uint32, app ApplicationID, at time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.cache[pid] = cachedApp{app: app, expires: at.Add(cacheTTL)}
}
