package discover

import (
	"log/slog"
	"os"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	obiDiscover "go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"

	"github.com/grafana/beyla/v3/pkg/beyla"
	servicesextra "github.com/grafana/beyla/v3/pkg/services"
)

var namespaceFetcherFunc = ebpfcommon.FindNetworkNamespace
var hasHostPidAccess = ebpfcommon.HasHostPidAccess
var osPidFunc = os.Getpid

func SurveyCriteriaMatcherProvider(
	cfg *beyla.Config,
	input *msg.Queue[[]obiDiscover.Event[obiDiscover.ProcessAttrs]],
	output *msg.Queue[[]obiDiscover.Event[obiDiscover.ProcessMatch]],
) swarm.InstanceFunc {
	beylaNamespace, _ := namespaceFetcherFunc(app.PID(osPidFunc()))
	m := &obiDiscover.Matcher{
		Log:              slog.With("component", "obiDiscover.SurveyCriteriaMatcher"),
		Criteria:         surveyCriteria(cfg),
		ExcludeCriteria:  surveyExcludingCriteria(cfg),
		ProcessHistory:   map[app.PID]obiDiscover.ProcessMatch{},
		Input:            input.Subscribe(msg.SubscriberName("surveyInput")),
		Output:           output,
		Namespace:        beylaNamespace,
		HasHostPidAccess: hasHostPidAccess(),
	}
	return swarm.DirectInstance(m.Run)
}

func surveyCriteria(cfg *beyla.Config) []services.Selector {
	survey := cfg.Discovery.Survey
	globs := make(services.GlobDefinitionCriteria, len(survey))

	for i := range survey {
		globs[i] = survey[i].GlobAttributes
		// Socket activity can also be the only selection criterion.
		if survey[i].SocketApps && !globs[i].Path.IsSet() {
			globs[i].Path = services.NewGlob("*")
		}
	}

	criteria := obiDiscover.NormalizeGlobCriteria(globs)
	for i := range criteria {
		// Keep the survey extension on the selectors carried in ProcessMatch,
		// including matches inherited from a parent process.
		criteria[i] = &servicesextra.SurveySelector{
			GlobAttributes: globs[i], SocketApps: survey[i].SocketApps,
		}
	}

	return criteria
}

func surveyExcludingCriteria(cfg *beyla.Config) []services.Selector {
	return obiDiscover.ExcludingCriteria(cfg.AsOBI())
}
