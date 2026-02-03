package webhook

import (
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"

	"github.com/grafana/beyla/v3/pkg/beyla"
)

type PodMatcher struct {
	logger    *slog.Logger
	selectors []services.Selector
}

func NewPodMatcher(cfg *beyla.Config) *PodMatcher {
	selectors := discover.NormalizeGlobCriteria(cfg.Injector.Instrument)
	logger := slog.With("component", "webhook.Matcher")

	logger.Debug("SDK instrumentation criteria", "selectors", selectors)

	return &PodMatcher{
		logger:    logger,
		selectors: selectors,
	}
}

func (m *PodMatcher) HasSelectionCriteria() bool {
	return len(m.selectors) > 0
}

func (m *PodMatcher) MatchProcessInfo(info *ProcessInfo) (services.Selector, bool) {
	for _, s := range m.selectors {
		if m.matchProcess(info, s) {
			return s, true
		}
	}

	return nil, false
}

func (m *PodMatcher) matchProcess(actual *ProcessInfo, required services.Selector) bool {
	if required == nil {
		return false
	}
	if actual == nil {
		return false
	}

	matchedAny := false

	// match metadata
	for attrName, criteriaRegexp := range required.RangeMetadata() {
		if attrValue, ok := actual.metadata[attrName]; !ok || !criteriaRegexp.MatchString(attrValue) {
			m.logger.Debug("metadata does not match", "attr", attrName, "value", attrValue)
			return false
		}
		matchedAny = true
	}

	// match pod labels
	for labelName, criteriaRegexp := range required.RangePodLabels() {
		if actualPodLabelValue, ok := actual.podLabels[labelName]; !ok || !criteriaRegexp.MatchString(actualPodLabelValue) {
			m.logger.Debug("pod label does not match", "label", labelName, "value", actualPodLabelValue)
			return false
		}
		matchedAny = true
	}

	// match pod annotations
	for annotationName, criteriaRegexp := range required.RangePodAnnotations() {
		if actualPodAnnotationValue, ok := actual.podAnnotations[annotationName]; !ok || !criteriaRegexp.MatchString(actualPodAnnotationValue) {
			m.logger.Debug("pod annotation does not match", "annotation", annotationName, "value", actualPodAnnotationValue)
			return false
		}
		matchedAny = true
	}

	return matchedAny
}
