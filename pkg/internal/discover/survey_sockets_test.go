package discover

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	obiDiscover "go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"

	"github.com/grafana/beyla/v3/pkg/internal/ebpf/surveywatcher"
	servicesextra "github.com/grafana/beyla/v3/pkg/services"
)

type fakeSocketProcesses struct{ snapshot surveywatcher.Snapshot }

func (s *fakeSocketProcesses) Snapshot() surveywatcher.Snapshot { return s.snapshot }
func (*fakeSocketProcesses) Changes() <-chan struct{}           { return nil }

type fakeSurveyPIDRegistry struct {
	aliases map[app.PID][]app.PID
	current map[uint32]map[app.PID]svc.Attrs
}

func (r *fakeSurveyPIDRegistry) AllowPID(pid app.PID, ns uint32, fi *exec.FileInfo, _ ebpfcommon.PIDType) {
	if r.current[ns] == nil {
		r.current[ns] = map[app.PID]svc.Attrs{}
	}
	for _, alias := range append([]app.PID{pid}, r.aliases[pid]...) {
		r.current[ns][alias] = fi.ServiceAttrs()
	}
}

func (r *fakeSurveyPIDRegistry) BlockPID(pid app.PID, ns uint32) {
	for alias := range r.current[ns] {
		if r.current[ns][alias].ProcPID == pid {
			delete(r.current[ns], alias)
		}
	}
	if len(r.current[ns]) == 0 {
		delete(r.current, ns)
	}
}

func (r *fakeSurveyPIDRegistry) CurrentPIDs(ebpfcommon.PIDType) map[uint32]map[app.PID]svc.Attrs {
	return r.current
}

func socketMatch(pid app.PID, kind obiDiscover.WatchEventType) surveyMatch {
	return surveyMatch{Type: kind, Obj: obiDiscover.ProcessMatch{
		Process:  &services.ProcessInfo{Pid: pid, ExePath: "/app"},
		Criteria: []services.Selector{&servicesextra.SurveySelector{SocketApps: servicesextra.SocketAppSelector{Enabled: true}}},
	}}
}

func nonRootSocketMatch(pid app.PID, kind obiDiscover.WatchEventType) surveyMatch {
	match := socketMatch(pid, kind)
	match.Obj.Criteria = []services.Selector{&servicesextra.SurveySelector{
		SocketApps: servicesextra.SocketAppSelector{Enabled: true, NonRoot: true},
	}}
	return match
}

func newTestSocketFilter() (*surveySocketFilter, *fakeSocketProcesses, map[app.PID]uint64) {
	sockets := &fakeSocketProcesses{snapshot: surveywatcher.Snapshot{}}
	lifetimes := map[app.PID]uint64{10: 100, 20: 200}
	f := &surveySocketFilter{
		sockets: sockets, processes: map[app.PID]socketCandidate{},
		pids:      &fakeSurveyPIDRegistry{aliases: map[app.PID][]app.PID{}, current: map[uint32]map[app.PID]svc.Attrs{}},
		namespace: func(app.PID) (uint32, error) { return 0, nil },
		realUID:   func(app.PID) (uint32, error) { return 1000, nil },
		startTime: func(pid app.PID) (uint64, error) {
			start, ok := lifetimes[pid]
			if !ok {
				return 0, os.ErrNotExist
			}
			return start, nil
		},
	}
	return f, sockets, lifetimes
}

func TestSurveySocketFilterPromotesAndKeepsAdmission(t *testing.T) {
	f, sockets, _ := newTestSocketFilter()
	created := socketMatch(10, obiDiscover.EventCreated)
	require.Empty(t, f.filter([]surveyMatch{created}))
	require.Len(t, f.processes, 1)
	sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100}] = struct{}{}
	assert.Equal(t, []surveyMatch{created}, f.promote())
	assert.Empty(t, f.promote(), "promotion must be emitted only once")
	assert.Empty(t, f.filter([]surveyMatch{created}), "repeated discovery must not duplicate creation")
	clear(sockets.snapshot)
	assert.Empty(t, f.promote(), "closing sockets must not revoke admission")
	deleted := socketMatch(10, obiDiscover.EventDeleted)
	assert.Equal(t, []surveyMatch{deleted}, f.filter([]surveyMatch{deleted}))
	assert.Empty(t, f.processes)
	assert.Empty(t, f.pids.CurrentPIDs(ebpfcommon.PIDTypeKProbes))
}

func TestSurveySocketFilterMixedSelectors(t *testing.T) {
	for _, unrestrictedFirst := range []bool{false, true} {
		name := "socket selector first"
		if unrestrictedFirst {
			name = "unrestricted selector first"
		}
		t.Run(name, func(t *testing.T) {
			f, sockets, _ := newTestSocketFilter()
			held := socketMatch(10, obiDiscover.EventCreated)
			immediate := socketMatch(20, obiDiscover.EventCreated)
			unrestricted := &servicesextra.SurveySelector{}
			if unrestrictedFirst {
				immediate.Obj.Criteria = append([]services.Selector{unrestricted}, immediate.Obj.Criteria...)
			} else {
				immediate.Obj.Criteria = append(immediate.Obj.Criteria, unrestricted)
			}

			assert.Equal(t, []surveyMatch{immediate}, f.filter([]surveyMatch{held, immediate}))
			assert.NotContains(t, f.processes, app.PID(20), "unrestricted matches don't need socket tracking")
			sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100}] = struct{}{}
			sockets.snapshot[surveywatcher.Process{PID: 20, StartTime: 200}] = struct{}{}
			assert.Equal(t, []surveyMatch{held}, f.promote(), "don't duplicate the unrestricted match")
			assert.Empty(t, f.promote())

			held.Type = obiDiscover.EventDeleted
			immediate.Type = obiDiscover.EventDeleted
			assert.Equal(t, []surveyMatch{held, immediate}, f.filter([]surveyMatch{held, immediate}))
			assert.Empty(t, f.processes)
		})
	}
}

func TestSurveySocketFilterUnrestrictedDoesNotRequireProcAccess(t *testing.T) {
	f, _, lifetimes := newTestSocketFilter()
	delete(lifetimes, 10)
	created := socketMatch(10, obiDiscover.EventCreated)
	created.Obj.Criteria = []services.Selector{&servicesextra.SurveySelector{}}
	assert.Equal(t, []surveyMatch{created}, f.filter([]surveyMatch{created}))
	deleted := created
	deleted.Type = obiDiscover.EventDeleted
	assert.Equal(t, []surveyMatch{deleted}, f.filter([]surveyMatch{deleted}))
	assert.Empty(t, f.processes)
}

func TestSurveySocketFilterEvidenceBeforeDiscovery(t *testing.T) {
	f, sockets, _ := newTestSocketFilter()
	sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100}] = struct{}{}
	created := socketMatch(10, obiDiscover.EventCreated)
	assert.Equal(t, []surveyMatch{created}, f.filter([]surveyMatch{created, socketMatch(20, obiDiscover.EventCreated)}))
	assert.Len(t, f.processes, 2)
	assert.False(t, f.processes[20].admitted)
}

func TestSurveySocketFilterDeletesPendingCandidates(t *testing.T) {
	f, sockets, _ := newTestSocketFilter()
	assert.Empty(t, f.filter([]surveyMatch{socketMatch(10, obiDiscover.EventCreated), socketMatch(10, obiDiscover.EventDeleted)}))
	assert.Empty(t, f.processes)
	sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100}] = struct{}{}
	assert.Empty(t, f.promote(), "late evidence must not resurrect a deleted candidate")
}

func TestSurveySocketFilterPIDReuse(t *testing.T) {
	f, sockets, lifetimes := newTestSocketFilter()
	sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100}] = struct{}{}
	created := socketMatch(10, obiDiscover.EventCreated)
	require.Len(t, f.filter([]surveyMatch{created}), 1)
	lifetimes[10] = 101
	assert.Equal(t, []surveyMatch{socketMatch(10, obiDiscover.EventDeleted)}, f.filter([]surveyMatch{created}))
	assert.False(t, f.processes[10].admitted)
	assert.Empty(t, f.promote(), "the previous lifetime's evidence doesn't apply")
	sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 101}] = struct{}{}
	assert.Equal(t, []surveyMatch{created}, f.promote())
}

func TestSurveySocketFilterDoesNotPromoteDeadOrReusedCandidates(t *testing.T) {
	for _, reused := range []bool{false, true} {
		f, sockets, lifetimes := newTestSocketFilter()
		require.Empty(t, f.filter([]surveyMatch{socketMatch(10, obiDiscover.EventCreated)}))
		if reused {
			lifetimes[10] = 101
		} else {
			delete(lifetimes, 10)
		}
		sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100}] = struct{}{}
		assert.Empty(t, f.promote())
		assert.Empty(t, f.processes)
	}
}

func TestSurveySocketFilterProcessGoneBeforeDiscovery(t *testing.T) {
	f, _, lifetimes := newTestSocketFilter()
	delete(lifetimes, 10)
	assert.Empty(t, f.filter([]surveyMatch{socketMatch(10, obiDiscover.EventCreated)}))
	assert.Empty(t, f.processes)
}

func TestRequiresNonRoot(t *testing.T) {
	assert.False(t, requiresNonRoot(socketMatch(10, obiDiscover.EventCreated)))
	assert.True(t, requiresNonRoot(nonRootSocketMatch(10, obiDiscover.EventCreated)))

	// A plain socket selector alongside a non-root one admits root processes.
	mixed := nonRootSocketMatch(10, obiDiscover.EventCreated)
	mixed.Obj.Criteria = append(mixed.Obj.Criteria,
		&servicesextra.SurveySelector{SocketApps: servicesextra.SocketAppSelector{Enabled: true}})
	assert.False(t, requiresNonRoot(mixed))
}

func TestSurveySocketFilterNonRoot(t *testing.T) {
	t.Run("real uid matches euid", func(t *testing.T) {
		uid, err := processRealUID(app.PID(os.Getpid()))
		require.NoError(t, err)
		assert.Equal(t, uint32(os.Getuid()), uid)
	})

	t.Run("privileged flag admits root", func(t *testing.T) {
		f, sockets, _ := newTestSocketFilter()
		f.realUID = func(app.PID) (uint32, error) { return 0, nil }
		created := nonRootSocketMatch(10, obiDiscover.EventCreated)
		require.Empty(t, f.filter([]surveyMatch{created}))
		require.True(t, f.processes[10].rootOnly)
		sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100, Flags: surveywatcher.FlagAny | surveywatcher.FlagPrivileged}] = struct{}{}
		assert.Equal(t, []surveyMatch{created}, f.promote())
	})

	t.Run("unprivileged listener holds root", func(t *testing.T) {
		f, sockets, _ := newTestSocketFilter()
		f.realUID = func(app.PID) (uint32, error) { return 0, nil }
		created := nonRootSocketMatch(10, obiDiscover.EventCreated)
		require.Empty(t, f.filter([]surveyMatch{created}))
		sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100, Flags: surveywatcher.FlagAny | surveywatcher.FlagNonPrivileged}] = struct{}{}
		assert.Empty(t, f.promote(), "root process with only high-port listeners must stay held")
		assert.False(t, f.processes[10].admitted)
	})

	t.Run("unprivileged listener admits non-root", func(t *testing.T) {
		f, sockets, _ := newTestSocketFilter()
		f.realUID = func(app.PID) (uint32, error) { return 1000, nil }
		created := nonRootSocketMatch(10, obiDiscover.EventCreated)
		require.Empty(t, f.filter([]surveyMatch{created}))
		require.False(t, f.processes[10].rootOnly)
		sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100, Flags: surveywatcher.FlagAny | surveywatcher.FlagNonPrivileged}] = struct{}{}
		assert.Equal(t, []surveyMatch{created}, f.promote())
	})

	t.Run("uid read failure admits", func(t *testing.T) {
		f, sockets, _ := newTestSocketFilter()
		f.realUID = func(app.PID) (uint32, error) { return 0, os.ErrNotExist }
		created := nonRootSocketMatch(10, obiDiscover.EventCreated)
		require.Empty(t, f.filter([]surveyMatch{created}))
		require.False(t, f.processes[10].rootOnly, "unknown uid must not hold the candidate")
		sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100, Flags: surveywatcher.FlagAny | surveywatcher.FlagNonPrivileged}] = struct{}{}
		assert.Equal(t, []surveyMatch{created}, f.promote())
	})

	t.Run("root admitted without non-root selector", func(t *testing.T) {
		f, sockets, _ := newTestSocketFilter()
		f.realUID = func(app.PID) (uint32, error) { return 0, nil }
		created := socketMatch(10, obiDiscover.EventCreated)
		require.Empty(t, f.filter([]surveyMatch{created}))
		require.False(t, f.processes[10].rootOnly, "plain socket selector never restricts root")
		sockets.snapshot[surveywatcher.Process{PID: 10, StartTime: 100, Flags: surveywatcher.FlagAny | surveywatcher.FlagNonPrivileged}] = struct{}{}
		assert.Equal(t, []surveyMatch{created}, f.promote())
	})
}

func TestSurveyProcessStartTime(t *testing.T) {
	start, err := processStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	assert.Positive(t, start)
}

func TestSurveySocketFilterPIDNamespaceAliases(t *testing.T) {
	f, sockets, lifetimes := newTestSocketFilter()
	registry := f.pids.(*fakeSurveyPIDRegistry)
	registry.aliases[10] = []app.PID{100, 1}
	registry.aliases[20] = []app.PID{200, 1}
	// Identical namespace-local PIDs and start times must remain distinct.
	lifetimes[20] = lifetimes[10]
	f.namespace = func(pid app.PID) (uint32, error) { return uint32(pid) * 100, nil }
	first := socketMatch(10, obiDiscover.EventCreated)
	second := socketMatch(20, obiDiscover.EventCreated)
	require.Empty(t, f.filter([]surveyMatch{first, second}))

	sockets.snapshot[surveywatcher.Process{Namespace: 1000, PID: 1, StartTime: 100}] = struct{}{}
	assert.Equal(t, []surveyMatch{first}, f.promote())
	assert.False(t, f.processes[20].admitted)
	// Another alias of an admitted process must not emit a duplicate event.
	sockets.snapshot[surveywatcher.Process{Namespace: 1000, PID: 100, StartTime: 100}] = struct{}{}
	assert.Empty(t, f.promote())

	sockets.snapshot[surveywatcher.Process{Namespace: 2000, PID: 1, StartTime: 100}] = struct{}{}
	assert.Equal(t, []surveyMatch{second}, f.promote())
	deleted := socketMatch(10, obiDiscover.EventDeleted)
	assert.Equal(t, []surveyMatch{deleted}, f.filter([]surveyMatch{deleted}))
	assert.NotContains(t, registry.current, uint32(1000), "remove all aliases for a deleted candidate")
	assert.Contains(t, registry.current[2000], app.PID(1), "preserve the other namespace's PID")
}

func TestSurveySocketFilterAliasPIDReuse(t *testing.T) {
	f, sockets, lifetimes := newTestSocketFilter()
	f.pids.(*fakeSurveyPIDRegistry).aliases[10] = []app.PID{1}
	f.namespace = func(app.PID) (uint32, error) { return 1000, nil }
	created := socketMatch(10, obiDiscover.EventCreated)
	require.Empty(t, f.filter([]surveyMatch{created}))
	lifetimes[10] = 101
	sockets.snapshot[surveywatcher.Process{Namespace: 1000, PID: 1, StartTime: 100}] = struct{}{}
	assert.Empty(t, f.promote(), "late evidence must not promote a reused procfs PID")
	assert.Empty(t, f.pids.CurrentPIDs(ebpfcommon.PIDTypeKProbes))
	require.Empty(t, f.filter([]surveyMatch{created}))
	sockets.snapshot[surveywatcher.Process{Namespace: 1000, PID: 1, StartTime: 101}] = struct{}{}
	assert.Equal(t, []surveyMatch{created}, f.promote())
}

func TestSurveySocketFilterUsesOBIPIDRegistry(t *testing.T) {
	pid := app.PID(os.Getpid())
	start, err := processStartTime(pid)
	require.NoError(t, err)
	ns, err := processNamespace(pid)
	require.NoError(t, err)
	registry := ebpfcommon.NewPIDsFilter(&services.DiscoveryConfig{}, slog.Default(), nil)
	sockets := &fakeSocketProcesses{snapshot: surveywatcher.Snapshot{}}
	f := &surveySocketFilter{
		sockets: sockets, pids: registry, processes: map[app.PID]socketCandidate{},
		startTime: processStartTime, namespace: processNamespace,
	}
	created := socketMatch(pid, obiDiscover.EventCreated)
	require.Empty(t, f.filter([]surveyMatch{created}))
	aliases := registry.CurrentPIDs(ebpfcommon.PIDTypeKProbes)[ns]
	require.Contains(t, aliases, pid)
	for alias := range aliases {
		assert.Equal(t, pid, aliases[alias].ProcPID)
		sockets.snapshot[surveywatcher.Process{Namespace: ns, PID: uint32(alias), StartTime: start}] = struct{}{}
	}
	assert.Equal(t, []surveyMatch{created}, f.promote())
	deleted := socketMatch(pid, obiDiscover.EventDeleted)
	assert.Equal(t, []surveyMatch{deleted}, f.filter([]surveyMatch{deleted}))
	assert.Empty(t, registry.CurrentPIDs(ebpfcommon.PIDTypeKProbes)[ns])
}
