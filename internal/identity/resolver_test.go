package identity

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	resolverNow = time.Date(2026, 10, 26, 9, 41, 53, 0, time.UTC)
	zenApp      = NewApplicationID(zenPath, zenSigner)
	mdnsApp     = NewApplicationID(mdnsPath, mdnsSigner)
	opencodeApp = NewApplicationID(opencodePath, opencodeSigner)
	cursorApp   = NewApplicationID(cursorPath, "")
)

type fakePort struct {
	infos map[uint32]ProcessInfo
	errs  map[uint32]error
	calls []uint32
}

func (f *fakePort) Lookup(pid uint32) (ProcessInfo, error) {
	f.calls = append(f.calls, pid)
	if err, ok := f.errs[pid]; ok {
		return ProcessInfo{}, err
	}
	if info, ok := f.infos[pid]; ok {
		return info, nil
	}
	return ProcessInfo{}, ErrProcessGone
}

func procInfo(pid uint32, start time.Time, name, path, signer string) ProcessInfo {
	return ProcessInfo{
		Key:    NewProcessKey(pid, start),
		Name:   name,
		Path:   path,
		Signer: signer,
	}
}

func TestResolveKnownProcess(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		10196: procInfo(10196, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
	}}

	require.Equal(t, zenApp, NewResolver(port).Resolve(ProcessRef{PID: 10196}, resolverNow))
	require.Equal(t, []uint32{10196}, port.calls)
}

func TestResolveSameProgramDifferentPIDs(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		17071: procInfo(17071, resolverNow.Add(-2*time.Hour), "node", cursorPath, ""),
		83144: procInfo(83144, resolverNow.Add(-time.Hour), "node", cursorPath, ""),
	}}
	r := NewResolver(port)

	a := r.Resolve(ProcessRef{PID: 17071}, resolverNow)
	b := r.Resolve(ProcessRef{PID: 83144}, resolverNow)

	require.Equal(t, cursorApp, a)
	require.Equal(t, a, b)
	require.Equal(t, []uint32{17071, 83144}, port.calls)
}

func TestResolveDifferentPathsDifferentApps(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		17071: procInfo(17071, resolverNow.Add(-time.Hour), "node", "/opt/homebrew/bin/node", ""),
		83144: procInfo(83144, resolverNow.Add(-time.Hour), "node", "/usr/local/bin/node", ""),
	}}
	r := NewResolver(port)

	require.NotEqual(t,
		r.Resolve(ProcessRef{PID: 17071}, resolverNow),
		r.Resolve(ProcessRef{PID: 83144}, resolverNow),
	)
}

func TestResolveCachesWithinTTL(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		10196: procInfo(10196, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
	}}
	r := NewResolver(port)

	r.Resolve(ProcessRef{PID: 10196}, resolverNow)
	r.Resolve(ProcessRef{PID: 10196}, resolverNow.Add(10*time.Second))

	require.Equal(t, []uint32{10196}, port.calls)
}

func TestResolveRefreshesAfterTTL(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		10196: procInfo(10196, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
	}}
	r := NewResolver(port)

	r.Resolve(ProcessRef{PID: 10196}, resolverNow)
	r.Resolve(ProcessRef{PID: 10196}, resolverNow.Add(31*time.Second))

	require.Len(t, port.calls, 2)
}

func TestResolveKeepsLastKnownAppAfterExit(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		10196: procInfo(10196, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
	}}
	r := NewResolver(port)

	require.Equal(t, zenApp, r.Resolve(ProcessRef{PID: 10196}, resolverNow))

	port.errs = map[uint32]error{10196: ErrProcessGone}
	require.Equal(t, zenApp, r.Resolve(ProcessRef{PID: 10196}, resolverNow.Add(31*time.Second)))

	calls := len(port.calls)
	require.Equal(t, zenApp, r.Resolve(ProcessRef{PID: 10196}, resolverNow.Add(40*time.Second)))
	require.Len(t, port.calls, calls, "a dead PID must not be looked up on every packet")
}

func TestResolveReusedPID(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		400: procInfo(400, resolverNow.Add(-time.Hour), "nsurlsessiond", "/usr/libexec/nsurlsessiond", ""),
	}}
	r := NewResolver(port)
	require.False(t, r.Resolve(ProcessRef{PID: 400}, resolverNow).IsZero())

	// The PID now belongs to a process that started after the packet time.
	const curlPath = "/opt/homebrew/bin/curl"
	port.infos[400] = procInfo(400, resolverNow.Add(32*time.Second), "curl", curlPath, "")

	require.True(t, r.Resolve(ProcessRef{PID: 400}, resolverNow.Add(31*time.Second)).IsZero(),
		"credited a packet to a process that did not exist yet")
	require.Equal(t, NewApplicationID(curlPath, ""), r.Resolve(ProcessRef{PID: 400}, resolverNow.Add(33*time.Second)))
}

func TestResolveUnknownPID(t *testing.T) {
	t.Parallel()

	port := &fakePort{}
	require.True(t, NewResolver(port).Resolve(ProcessRef{PID: 99987}, resolverNow).IsZero())
	require.Equal(t, []uint32{99987}, port.calls)
}

func TestResolveZeroPID(t *testing.T) {
	t.Parallel()

	port := &fakePort{}
	require.True(t, NewResolver(port).Resolve(ProcessRef{}, resolverNow).IsZero())
	require.Empty(t, port.calls)
}

func TestResolveDelegatedUsesEffectivePID(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		400:   procInfo(400, resolverNow.Add(-time.Hour), "nsurlsessiond", "/usr/libexec/nsurlsessiond", ""),
		10196: procInfo(10196, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
	}}

	got := NewResolver(port).Resolve(ProcessRef{PID: 400, EffectivePID: 10196, Delegated: true}, resolverNow)

	require.Equal(t, zenApp, got)
	require.Equal(t, []uint32{10196}, port.calls)
}

func TestResolveDelegatedFallsBackWhenEffectiveGone(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		400: procInfo(400, resolverNow.Add(-time.Hour), "nsurlsessiond", "/usr/libexec/nsurlsessiond", ""),
	}}

	got := NewResolver(port).Resolve(ProcessRef{PID: 400, EffectivePID: 99987, Delegated: true}, resolverNow)

	require.Equal(t, NewApplicationID("/usr/libexec/nsurlsessiond", ""), got)
	require.Equal(t, []uint32{99987, 400}, port.calls)
}

func TestResolveDelegatedSamePID(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		10196: procInfo(10196, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
	}}

	require.Equal(t, zenApp, NewResolver(port).Resolve(ProcessRef{PID: 10196, EffectivePID: 10196, Delegated: true}, resolverNow))
	require.Equal(t, []uint32{10196}, port.calls)
}

func TestResolveIgnoresEffectivePIDWhenNotDelegated(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		10196: procInfo(10196, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
		83144: procInfo(83144, resolverNow.Add(-time.Hour), "node", cursorPath, ""),
	}}

	got := NewResolver(port).Resolve(ProcessRef{PID: 10196, EffectivePID: 83144}, resolverNow)

	require.Equal(t, zenApp, got)
	require.Equal(t, []uint32{10196}, port.calls)
}

func TestResolveDelegatedWithoutEffectivePID(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		10196: procInfo(10196, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
	}}

	require.Equal(t, zenApp, NewResolver(port).Resolve(ProcessRef{PID: 10196, Delegated: true}, resolverNow))
	require.Equal(t, []uint32{10196}, port.calls)
}

func TestResolveUnexpectedPortError(t *testing.T) {
	t.Parallel()

	port := &fakePort{errs: map[uint32]error{10196: ErrPermission}}
	require.True(t, NewResolver(port).Resolve(ProcessRef{PID: 10196}, resolverNow).IsZero())
	require.Equal(t, []uint32{10196}, port.calls)
}

func TestResolveMismatchedLookup(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		100: procInfo(999, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
	}}
	r := NewResolver(port)

	require.True(t, r.Resolve(ProcessRef{PID: 100}, resolverNow).IsZero())
	require.True(t, r.Resolve(ProcessRef{PID: 100}, resolverNow).IsZero())
	require.Len(t, port.calls, 2, "a mismatched lookup must not be cached")
}

func TestResolveEmptyPath(t *testing.T) {
	t.Parallel()

	port := &fakePort{infos: map[uint32]ProcessInfo{
		100: procInfo(100, resolverNow.Add(-time.Hour), "ghost", "", "TEAM:signed"),
	}}

	require.True(t, NewResolver(port).Resolve(ProcessRef{PID: 100}, resolverNow).IsZero())
}

func BenchmarkResolverResolve(b *testing.B) {
	b.Run("cache hit", func(b *testing.B) {
		port := &fakePort{infos: map[uint32]ProcessInfo{
			10196: procInfo(10196, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
		}}
		r := NewResolver(port)
		ref := ProcessRef{PID: 10196}

		b.ReportAllocs()
		for b.Loop() {
			if r.Resolve(ref, resolverNow).IsZero() {
				b.Fatal("unresolved")
			}
		}
	})

	b.Run("cache miss", func(b *testing.B) {
		port := &fakePort{infos: map[uint32]ProcessInfo{
			10196: procInfo(10196, resolverNow.Add(-time.Hour), "zen", zenPath, zenSigner),
		}}
		r := NewResolver(port)
		ref := ProcessRef{PID: 10196}
		at := resolverNow

		b.ReportAllocs()
		for b.Loop() {
			at = at.Add(31 * time.Second)
			if r.Resolve(ref, at).IsZero() {
				b.Fatal("unresolved")
			}
		}
	})
}
