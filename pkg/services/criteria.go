package services

import (
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/services"
)

// DiscoveryConfig for the discover.ProcessFinder pipeline
type BeylaDiscoveryConfig struct {
	services.DiscoveryConfig
	// Survey selection. Same as services selection, however, it generates only the target info (survey_info) instead of instrumenting the services
	Survey services.GlobDefinitionCriteria `yaml:"survey"`
}

func (d *BeylaDiscoveryConfig) SurveyEnabled() bool {
	return len(d.Survey) > 0
}

func (d *BeylaDiscoveryConfig) AppDiscoveryEnabled() bool {
	return len(d.Services) > 0 || len(d.Instrument) > 0
}
