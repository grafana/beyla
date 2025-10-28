package discover

import (
	"log/slog"
	"os"

	obiDiscover "go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

var namespaceFetcherFunc = ebpfcommon.FindNetworkNamespace
var hasHostPidAccess = ebpfcommon.HasHostPidAccess
var osPidFunc = os.Getpid

func SurveyCriteriaMatcherProvider(
	cfg *beyla.Config,
	input *msg.Queue[[]obiDiscover.Event[obiDiscover.ProcessAttrs]],
	output *msg.Queue[[]obiDiscover.Event[obiDiscover.ProcessMatch]],
) swarm.InstanceFunc {
	beylaNamespace, _ := namespaceFetcherFunc(int32(osPidFunc()))
	m := &obiDiscover.Matcher{
		Log:              slog.With("component", "obiDiscover.SurveyCriteriaMatcher"),
		Criteria:         surveyCriteria(cfg),
		ExcludeCriteria:  surveyExcludingCriteria(cfg),
		ProcessHistory:   map[obiDiscover.PID]obiDiscover.ProcessMatch{},
		Input:            input.Subscribe(msg.SubscriberName("surveyInput")),
		Output:           output,
		Namespace:        beylaNamespace,
		HasHostPidAccess: hasHostPidAccess(),
	}
	return swarm.DirectInstance(m.Run)
}

func surveyCriteria(cfg *beyla.Config) []services.Selector {
	finderCriteria := cfg.Discovery.Survey
	return obiDiscover.NormalizeGlobCriteria(finderCriteria)
}

func surveyExcludingCriteria(cfg *beyla.Config) []services.Selector {
	// deprecated options: supporting them only if the user neither defines
	// the instrument nor exclude_instrument sections
	obiCfg := cfg.AsOBI()
	if obiDiscover.OnlyDefinesDeprecatedServiceSelection(obiCfg) {
		return obiDiscover.RegexAsSelector(cfg.Discovery.DefaultExcludeServices)
	}
	return obiDiscover.GlobsAsSelector(cfg.Discovery.DefaultExcludeInstrument)
}
