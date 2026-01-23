package webhook

import (
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func wmlog() *slog.Logger {
	return slog.With("component", "webhook.Matcher")
}

func matchProcessInfo(info *ProcessInfo, selectors []services.Selector) bool {
	log := wmlog()
	for _, s := range selectors {
		if matchProcess(log, info, s) {
			return true
		}
	}

	return false
}

func matchProcess(log *slog.Logger, obj *ProcessInfo, a services.Selector) bool {
	if !a.GetPath().IsSet() && a.GetOpenPorts().Len() == 0 && len(obj.metadata) == 0 {
		log.Info("no Kube metadata, no local selection criteria. Ignoring")
		return false
	}
	if (a.GetPath().IsSet() || a.GetPathRegexp().IsSet()) && !matchByExecutable(obj, a) {
		log.Info("executable path does not match", "path", a.GetPath(), "pathregexp", a.GetPathRegexp())
		return false
	}
	if a.GetOpenPorts().Len() > 0 && !matchByPort(obj, a) {
		log.Info("open ports do not match", "openPorts", a.GetOpenPorts(), "process ports", obj.openPorts)
		return false
	}
	// after matching by process basic information, we check if it matches
	// by metadata.
	// If there is no metadata, this will return true.
	return matchByAttributes(log, obj, a)
}

func matchByPort(p *ProcessInfo, a services.Selector) bool {
	for _, c := range p.openPorts {
		if a.GetOpenPorts().Matches(int(c)) {
			return true
		}
	}
	return false
}

func matchByExecutable(p *ProcessInfo, a services.Selector) bool {
	if a.GetPath().IsSet() {
		return a.GetPath().MatchString(p.exePath)
	}
	return a.GetPathRegexp().MatchString(p.exePath)
}

func matchByAttributes(log *slog.Logger, actual *ProcessInfo, required services.Selector) bool {
	if required == nil {
		return true
	}
	if actual == nil {
		return false
	}
	// match metadata
	for attrName, criteriaRegexp := range required.RangeMetadata() {
		if attrValue, ok := actual.metadata[attrName]; !ok || !criteriaRegexp.MatchString(attrValue) {
			log.Info("metadata does not match", "attr", attrName, "value", attrValue)
			return false
		}
	}

	// match pod labels
	for labelName, criteriaRegexp := range required.RangePodLabels() {
		if actualPodLabelValue, ok := actual.podLabels[labelName]; !ok || !criteriaRegexp.MatchString(actualPodLabelValue) {
			log.Info("pod label does not match", "label", labelName, "value", actualPodLabelValue)
			return false
		}
	}

	// match pod annotations
	for annotationName, criteriaRegexp := range required.RangePodAnnotations() {
		if actualPodAnnotationValue, ok := actual.podAnnotations[annotationName]; !ok || !criteriaRegexp.MatchString(actualPodAnnotationValue) {
			log.Info("pod annotation does not match", "annotation", annotationName, "value", actualPodAnnotationValue)
			return false
		}
	}
	return true
}
