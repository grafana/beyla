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
}

func NewPodMatcher(cfg *beyla.Config) *PodMatcher {
	logger := slog.With("component", "webhook.Matcher")
	logger.Debug("SDK instrumentation criteria", "selectors", cfg.Injector.Instrument)
	return &PodMatcher{
		logger:     logger,
		instrument: cfg.Injector.Instrument,
	}
}

func (m *PodMatcher) HasSelectionCriteria() bool {
	return len(m.instrument) > 0
}

func (m *PodMatcher) MatchProcessInfo(info *ProcessInfo) (configmap.Selector, bool) {
	if info == nil {
		return configmap.Selector{}, false
	}
	input := configmap.MatchInput{
		Namespace:   info.metadata[services.AttrNamespace],
		OwnerChain:  info.ownerChain,
		Labels:      info.podLabels,
		Annotations: info.podAnnotations,
	}
	for _, sel := range m.instrument {
		if sel.Match(input) {
			return sel, true
		}
	}
	return configmap.Selector{}, false
}
