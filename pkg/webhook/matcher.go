package webhook

import (
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/services"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

type PodMatcher struct {
	logger     *slog.Logger
	instrument configmap.WebhookInstrument
	exclude    configmap.WebhookInstrument
}

func NewPodMatcher(cfg *beyla.Config) *PodMatcher {
	logger := slog.With("component", "webhook.Matcher")
	logger.Debug("SDK instrumentation criteria",
		"selectors", cfg.Injector.Instrument, "exclude", cfg.Injector.ExcludeInstrument)
	return &PodMatcher{
		logger:     logger,
		instrument: cfg.Injector.Instrument,
		exclude:    cfg.Injector.ExcludeInstrument,
	}
}

func (m *PodMatcher) HasSelectionCriteria() bool {
	return len(m.instrument) > 0
}

func (m *PodMatcher) MatchProcessInfo(info *ProcessInfo) (configmap.K8sSelector, bool) {
	if info == nil {
		return configmap.K8sSelector{}, false
	}
	input := configmap.MatchInput{
		Namespace:   info.metadata[services.AttrNamespace],
		OwnerChain:  info.ownerChain,
		Labels:      info.podLabels,
		Annotations: info.podAnnotations,
	}
	// Exclusion always wins: a pod matching any exclude selector is never
	// instrumented, even if it also matches an instrument selector. This mirrors
	// the skip rules buildInjectConfig emits for the external injector.
	for _, sel := range m.exclude {
		if sel.Match(input) {
			return configmap.K8sSelector{}, false
		}
	}
	for _, sel := range m.instrument {
		if sel.Match(input) {
			return sel, true
		}
	}
	return configmap.K8sSelector{}, false
}
