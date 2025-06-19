package discover

import (
	"log/slog"
	"os"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/discover"
	ebpfcommon "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/common"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/services"

	"github.com/grafana/beyla/v2/pkg/beyla"
)

var namespaceFetcherFunc = ebpfcommon.FindNetworkNamespace
var hasHostPidAccess = ebpfcommon.HasHostPidAccess
var osPidFunc = os.Getpid

func SurveyCriteriaMatcherProvider(
	cfg *beyla.Config,
	input *msg.Queue[[]discover.Event[discover.ProcessAttrs]],
	output *msg.Queue[[]discover.Event[discover.ProcessMatch]],
) swarm.InstanceFunc {
	beylaNamespace, _ := namespaceFetcherFunc(int32(osPidFunc()))
	m := &discover.Matcher{
		Log:              slog.With("component", "discover.SurveyCriteriaMatcher"),
		Criteria:         surveyCriteria(cfg),
		ExcludeCriteria:  surveyExcludingCriteria(cfg),
		ProcessHistory:   map[discover.PID]*services.ProcessInfo{},
		Input:            input.Subscribe(),
		Output:           output,
		Namespace:        beylaNamespace,
		HasHostPidAccess: hasHostPidAccess(),
	}
	return swarm.DirectInstance(m.Run)
}

func surveyCriteria(cfg *beyla.Config) []services.Selector {
	finderCriteria := cfg.Discovery.Survey
	return discover.NormalizeGlobCriteria(finderCriteria)
}

func surveyExcludingCriteria(cfg *beyla.Config) []services.Selector {
	// deprecated options: supporting them only if the user neither defines
	// the instrument nor exclude_instrument sections
	obiCfg := cfg.AsOBI()
	if discover.OnlyDefinesDeprecatedServiceSelection(obiCfg) {
		return discover.RegexAsSelector(cfg.Discovery.DefaultExcludeServices)
	}
	return discover.GlobsAsSelector(cfg.Discovery.DefaultExcludeInstrument)
}
