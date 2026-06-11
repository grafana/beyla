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
		instrument: selectorsFromDefinitionCriteria(cfg.Injector.Instrument),
		exclude:    selectorsFromDefinitionCriteria(cfg.Injector.ExcludeInstrument),
	}
}

func selectorFromGlob(a *services.GlobAttributes) *configmap.K8sSelector {
	var podLabels map[string]services.GlobAttr
	if len(a.PodLabels) > 0 {
		podLabels = make(map[string]services.GlobAttr, len(a.PodLabels))
		for k, v := range a.PodLabels {
			podLabels[k] = *v
		}
	}

	var podAnnotations map[string]services.GlobAttr
	if len(a.PodAnnotations) > 0 {
		podAnnotations = make(map[string]services.GlobAttr, len(a.PodAnnotations))
		for k, v := range a.PodAnnotations {
			podAnnotations[k] = *v
		}
	}

	metaGlob := func(name string) []services.GlobAttr {
		if g := a.Metadata[name]; g != nil {
			return []services.GlobAttr{*g}
		}
		return nil
	}

	// First check to see if the user used k8s_owner_name
	ownerNames := metaGlob(services.AttrOwnerName)
	var kinds []string
	// If no owner name, then we check the specific types of definitions.
	// In this case we set both the owner name and the kind to match the new
	// service definition format.
	if ownerNames == nil {
		for _, owner := range []struct {
			metadataKey string
			kind        string
		}{
			{metadataKey: services.AttrDeploymentName, kind: "Deployment"},
			{metadataKey: services.AttrDaemonSetName, kind: "DaemonSet"},
			{metadataKey: services.AttrReplicaSetName, kind: "ReplicaSet"},
			{metadataKey: services.AttrStatefulSetName, kind: "StatefulSet"},
			{metadataKey: services.AttrJobName, kind: "Job"},
			{metadataKey: services.AttrCronJobName, kind: "CronJob"},
			{metadataKey: services.AttrPodName, kind: "Pod"},
		} {
			if names := metaGlob(owner.metadataKey); names != nil {
				ownerNames = names
				kinds = []string{owner.kind}
				break
			}
		}
	}

	sel := configmap.K8sSelector{
		Namespaces:     metaGlob(services.AttrNamespace),
		OwnerNames:     ownerNames,
		OwnerKinds:     kinds,
		PodLabels:      podLabels,
		PodAnnotations: podAnnotations,
	}

	if sel.IsEmpty() {
		return nil
	}

	return &sel
}

// nsScope is the pre-computed namespace scope derived from the injector config.
type nsScope struct {
	clusterWide bool
	globs       []*services.GlobAttr
}

// scopedNamespaces analyzes the injector configuration and returns an nsScope.
func (m *PodMatcher) scopedNamespaces() nsScope {
	for _, sel := range m.instrument {
		if len(sel.Namespaces) == 0 {
			return nsScope{clusterWide: true}
		}
	}
	var globs []*services.GlobAttr
	for _, sel := range m.instrument {
		for i := range sel.Namespaces {
			globs = append(globs, &sel.Namespaces[i])
		}
	}
	return nsScope{globs: globs}
}

func selectorsFromDefinitionCriteria(criteria services.GlobDefinitionCriteria) configmap.WebhookInstrument {
	instr := configmap.WebhookInstrument{}

	for i := range criteria {
		if sel := selectorFromGlob(&criteria[i]); sel != nil {
			instr = append(instr, *sel)
		}
	}

	return instr
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
