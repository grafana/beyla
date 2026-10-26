package discover

import (
	"context"

	obiDiscover "go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"

	"github.com/grafana/beyla/v3/pkg/internal/ebpf/surveywatcher"
	msg2 "github.com/grafana/beyla/v3/pkg/internal/helpers/msg"
	servicesextra "github.com/grafana/beyla/v3/pkg/services"
)

// connectSocketWatcher shares socket observation between survey and local instrumentation.
func (pf *ProcessFinder) connectSocketWatcher(swi *swarm.Instancer) *msg.Queue[surveywatcher.Snapshot] {
	if !pf.cfg.Discovery.InstrumentAllLocal && !pf.cfg.Discovery.Survey.SocketAppsEnabled() {
		return nil
	}
	snapshots := msg2.QueueFromConfig[surveywatcher.Snapshot](pf.cfg.AsOBI(), "socketSnapshots")
	swi.Add(socketWatcherProvider(pf.cfg.AsOBI(), pf.ebpfEventContext, snapshots), swarm.WithID("SocketWatcher"))
	return snapshots
}

// connectInstrumentAllLocal feeds socket-eligible applications into OBI's PID selector.
func (pf *ProcessFinder) connectInstrumentAllLocal(
	swi *swarm.Instancer,
	input *msg.Queue[[]obiDiscover.Event[obiDiscover.ProcessAttrs]],
	snapshots *msg.Queue[surveywatcher.Snapshot],
	selector *obiDiscover.DynamicSelector,
) {
	criteria := []services.Selector{&servicesextra.SurveySelector{
		GlobAttributes: services.GlobAttributes{Path: services.NewGlob("*")},
		SocketApps:     servicesextra.SocketAppSelector{Enabled: true, NonRoot: true},
	}}
	candidates := msg2.QueueFromConfig[[]surveyMatch](pf.cfg.AsOBI(), "localCandidates")
	swi.Add(criteriaMatcherProvider(pf.cfg, criteria, input, candidates), swarm.WithID("LocalCriteriaMatcher"))
	eligible := msg2.QueueFromConfig[[]surveyMatch](pf.cfg.AsOBI(), "localEligibleProcesses")
	swi.Add(surveySocketFilterProvider(pf.cfg.AsOBI(), snapshots, candidates, eligible), swarm.WithID("LocalSocketFilter"))
	swi.Add(localPIDSelectorProvider(selector, eligible), swarm.WithID("LocalPIDSelector"))
}

// localPIDSelectorProvider updates application PID selection as eligible processes come and go.
func localPIDSelectorProvider(selector *obiDiscover.DynamicSelector, input *msg.Queue[[]surveyMatch]) swarm.InstanceFunc {
	in := input.Subscribe()
	return swarm.DirectInstance(func(ctx context.Context) {
		swarms.ForEachInput(ctx, in, nil, func(batch []surveyMatch) {
			for _, event := range batch {
				pid := uint32(event.Obj.Process.Pid)
				switch event.Type {
				case obiDiscover.EventCreated:
					selector.Traces().AddPIDs(pid)
					selector.AppMetrics().AddPIDs(pid)
				case obiDiscover.EventDeleted:
					selector.Traces().RemovePIDs(pid)
					selector.AppMetrics().RemovePIDs(pid)
				}
			}
		})
	})
}
