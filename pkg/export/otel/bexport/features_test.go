package bexport

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/export"
)

func TestNoBitRangeCollision(t *testing.T) {
	// checks that any of the Beyla feature flags do not collide with OBI's features
	assert.False(t,
		Any(FeatureProcess|FeatureSurveyInfo,
			export.FeatureNetwork|
				export.FeatureNetworkInterZone|
				export.FeatureApplicationRED|
				export.FeatureSpanLegacy|
				export.FeatureSpanOTel|
				export.FeatureSpanSizes|
				export.FeatureGraph|
				export.FeatureApplicationHost|
				export.FeatureEBPF))
}

func TestMergingFeatures(t *testing.T) {
	type testCase struct {
		names     []string
		expect    export.Features
		hasSurvey bool
		hasProc   bool
	}
	for _, tc := range []testCase{{
		names:     []string{"application", "application_span", "application_service_graph"},
		expect:    export.FeatureApplicationRED | export.FeatureSpanLegacy | export.FeatureGraph,
		hasSurvey: false,
		hasProc:   false,
	}, {
		names:     []string{"application_process"},
		expect:    FeatureProcess,
		hasSurvey: false,
		hasProc:   true,
	}, {
		names:     []string{"survey_info"},
		expect:    FeatureSurveyInfo,
		hasSurvey: true,
		hasProc:   false,
	}, {
		names:     []string{"application_process", "survey_info"},
		expect:    FeatureSurveyInfo | FeatureProcess,
		hasSurvey: true,
		hasProc:   true,
	}, {
		names:     []string{"application", "application_span", "application_service_graph", "application_process"},
		expect:    export.FeatureApplicationRED | export.FeatureSpanLegacy | export.FeatureGraph | FeatureProcess,
		hasSurvey: false,
		hasProc:   true,
	}} {
		t.Run(strings.Join(tc.names, ","), func(t *testing.T) {
			f := export.LoadFeatures(tc.names)
			assert.Equal(t, tc.expect, f)
			assert.Equal(t, tc.hasProc, Any(f, FeatureProcess))
			assert.Equal(t, tc.hasSurvey, Any(f, FeatureSurveyInfo))
		})
	}
}
