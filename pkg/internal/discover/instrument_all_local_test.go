package discover

import (
	"context"
	"os"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	obiDiscover "go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/internal/ebpf/surveywatcher"
)

// TestLocalPIDSelectorLifecycle verifies application selection, deletion, and PID reuse.
func TestLocalPIDSelectorLifecycle(t *testing.T) {
	selector := obiDiscover.NewDynamicSelector()
	synctest.Test(t, func(t *testing.T) {
		input := msg.NewQueue[[]surveyMatch]()
		run, err := localPIDSelectorProvider(selector, input)(t.Context())
		require.NoError(t, err)
		done := make(chan struct{})
		go func() {
			run(t.Context())
			close(done)
		}()
		created := nonRootSocketMatch(10, obiDiscover.EventCreated)
		input.Send([]surveyMatch{created, created})
		synctest.Wait()
		assert.True(t, selector.Traces().IncludesPID(10))
		assert.True(t, selector.AppMetrics().IncludesPID(10))
		assert.False(t, selector.NetworkMetrics().IncludesPID(10))
		assert.False(t, selector.StatsMetrics().IncludesPID(10))
		input.Send([]surveyMatch{nonRootSocketMatch(10, obiDiscover.EventDeleted), created})
		synctest.Wait()
		assert.True(t, selector.IncludesPID(10), "a recycled PID can be admitted again")
		input.Send([]surveyMatch{nonRootSocketMatch(10, obiDiscover.EventDeleted)})
		synctest.Wait()
		assert.False(t, selector.IncludesPID(10))
		input.Close()
		<-done
	})
}

// TestLocalSelectionSharesSocketSnapshots verifies independent consumers and delayed socket admission.
func TestLocalSelectionSharesSocketSnapshots(t *testing.T) {
	selector := obiDiscover.NewDynamicSelector()
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cfg := beyla.DefaultConfig()
		cfg.Discovery.InstrumentAllLocal = true
		finder := &ProcessFinder{cfg: cfg}
		assert.True(t, finder.IsInstrumentationEnabled())
		assert.False(t, cfg.Discovery.SurveyEnabled())
		pid := app.PID(os.Getpid())
		start, err := processStartTime(pid)
		require.NoError(t, err)
		ns, err := processNamespace(pid)
		require.NoError(t, err)
		input := msg.NewQueue[[]surveyMatch]()
		snapshots := msg.NewQueue[surveywatcher.Snapshot]()
		eligible := msg.NewQueue[[]surveyMatch]()
		survey := msg.NewQueue[[]surveyMatch]()
		surveyEvents := survey.Subscribe()
		swi := swarm.Instancer{}
		swi.Add(surveySocketFilterProvider(cfg.AsOBI(), snapshots, input, eligible))
		swi.Add(surveySocketFilterProvider(cfg.AsOBI(), snapshots, input, survey))
		swi.Add(localPIDSelectorProvider(selector, eligible))
		pipeline, err := swi.Instance(ctx)
		require.NoError(t, err)
		pipeline.Start(ctx)
		created := nonRootSocketMatch(pid, obiDiscover.EventCreated)
		input.Send([]surveyMatch{created})
		synctest.Wait()
		assert.False(t, selector.IncludesPID(pid), "discovery alone must not admit a process")
		snapshots.Send(surveywatcher.Snapshot{{PID: uint32(pid), Namespace: ns, StartTime: start, Flags: surveywatcher.FlagPrivileged}: {}})
		synctest.Wait()
		assert.True(t, selector.Traces().IncludesPID(pid))
		assert.True(t, selector.AppMetrics().IncludesPID(pid))
		assert.Equal(t, []surveyMatch{created}, <-surveyEvents, "both filters must observe the same snapshot")
		snapshots.Send(surveywatcher.Snapshot{})
		synctest.Wait()
		assert.True(t, selector.IncludesPID(pid), "socket closure must not revoke admission")
		deleted := nonRootSocketMatch(pid, obiDiscover.EventDeleted)
		input.Send([]surveyMatch{deleted})
		synctest.Wait()
		assert.False(t, selector.IncludesPID(pid))
		assert.Equal(t, []surveyMatch{deleted}, <-surveyEvents)
		cancel()
		<-pipeline.Done()
	})
}
