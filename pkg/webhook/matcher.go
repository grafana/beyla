package webhook

import (
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/discover"
	"go.opentelemetry.io/obi/pkg/appolly/services"

	"github.com/grafana/beyla/v3/pkg/beyla"
	"github.com/grafana/beyla/v3/pkg/webhook/configmap"
)

type PodMatcher struct {
	logger    *slog.Logger
	selectors []services.Selector
}

func NewPodMatcher(cfg *beyla.Config) *PodMatcher {
	selectors := asProcessDiscoverySelector(cfg.Injector.Instrument)
	logger := slog.With("component", "webhook.Matcher")

	logger.Debug("SDK instrumentation criteria", "selectors", selectors)

	return &PodMatcher{
		logger:    logger,
		selectors: selectors,
	}
}

func asProcessDiscoverySelector(in configmap.WebhookInstrument) []services.Selector {
	out := make(services.GlobDefinitionCriteria, 0, len(in))
	for _, selector := range in {
		labels := globAttrPtrMap(selector.PodLabels)
		annotations := globAttrPtrMap(selector.PodAnnotations)
		metadata := services.MetadataGlobMap{}
		if selector.OwnerName.IsSet() {
			own := selector.OwnerName
			metadata[services.AttrOwnerName] = &own
		}
		if len(selector.Namespaces) == 0 {
			out = append(out, services.GlobAttributes{
				Metadata:       metadata,
				PodLabels:      labels,
				PodAnnotations: annotations,
			})
		} else {
			// Expand one entry per namespace so OR semantics are preserved.
			for _, ns := range selector.Namespaces {
				nsGlob := ns
				nsMetadata := make(services.MetadataGlobMap, len(metadata)+1)
				for k, v := range metadata {
					nsMetadata[k] = v
				}
				nsMetadata[services.AttrNamespace] = &nsGlob
				out = append(out, services.GlobAttributes{
					Metadata:       nsMetadata,
					PodLabels:      labels,
					PodAnnotations: annotations,
				})
			}
		}
	}
	return discover.NormalizeGlobCriteria(out)
}

func globAttrPtrMap(in map[string]services.GlobAttr) map[string]*services.GlobAttr {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]*services.GlobAttr, len(in))
	for k := range in {
		v := in[k]
		out[k] = &v
	}
	return out
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
