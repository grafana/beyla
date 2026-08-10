package bexport

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
)

func mustLoadFeatures(t *testing.T, names ...string) export.Features {
	t.Helper()
	features, err := export.LoadFeatures(names)
	require.NoError(t, err)
	return features
}

func TestNoBitRangeCollision(t *testing.T) {
	// checks that any of the Beyla feature flags do not collide with OBI's features
	assert.False(t,
		Any(FeatureProcess,
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
		names   []string
		expect  export.Features
		hasProc bool
	}
	for _, tc := range []testCase{{
		names:   []string{"application", "application_span", "application_service_graph"},
		expect:  export.FeatureApplicationRED | export.FeatureSpanLegacy | export.FeatureGraph,
		hasProc: false,
	}, {
		names:   []string{"application_process"},
		expect:  FeatureProcess,
		hasProc: true,
	}, {
		names:   []string{"application", "application_span", "application_service_graph", "application_process"},
		expect:  export.FeatureApplicationRED | export.FeatureSpanLegacy | export.FeatureGraph | FeatureProcess,
		hasProc: true,
	}} {
		t.Run(strings.Join(tc.names, ","), func(t *testing.T) {
			f := mustLoadFeatures(t, tc.names...)
			assert.Equal(t, tc.expect, f)
			assert.Equal(t, tc.hasProc, Any(f, FeatureProcess))
		})
	}
}

// ported from OBI's TestLoadFeaturesRejectsUnknownNames, with an extra case
// verifying that the Beyla-specific feature registered in init() passes the
// stricter validation.
func TestLoadFeaturesRejectsUnknownNames(t *testing.T) {
	type testCase struct {
		name        string
		names       []string
		errContains string
		expect      export.Features
	}
	for _, tc := range []testCase{{
		name:        "unknown feature",
		names:       []string{"application_jvm"},
		errContains: `unknown metrics feature "application_jvm"`,
	}, {
		name:        "typo in an otherwise valid list",
		names:       []string{"application", "application_runtme"},
		errContains: "application_runtme",
	}, {
		// empty entries (trailing commas in env values) are not an error
		name:   "empty entry is ignored",
		names:  []string{"application", ""},
		expect: export.FeatureApplicationRED,
	}, {
		// the error names the valid features so a typo is self-diagnosing
		name:        "error lists the valid features",
		names:       []string{"no_such_feature"},
		errContains: "application_runtime",
	}, {
		name:   "beyla extension is a valid name",
		names:  []string{"application_process"},
		expect: FeatureProcess,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := export.LoadFeatures(tc.names)
			if tc.errContains != "" {
				require.ErrorContains(t, err, tc.errContains)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expect, f)
		})
	}
}
