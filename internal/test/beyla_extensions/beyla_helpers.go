//go:build integration && obi_extension

// Beyla-specific test helpers
// This file is copied to internal/obi/test/integration/ by generate-obi-tests.sh

package integration

import (
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v3/internal/obi/test/integration/components/promtest"
)

// testPrometheusBeylaBuildInfo checks for Beyla build info metric
func testPrometheusBeylaBuildInfo(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	var results []promtest.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`beyla_build_info{target_lang="go"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	})
}

// testPrometheusNoBeylaEvents checks that Beyla self-instrumentation is disabled
func testPrometheusNoBeylaEvents(t *testing.T) {
	pq := promtest.Client{HostPort: prometheusHostPort}
	// Wait a bit to ensure metrics would have been collected if self-instrumentation was enabled
	time.Sleep(2 * time.Second)
	results, err := pq.Query(`http_server_request_duration_seconds_count{service_name="beyla"}`)
	require.NoError(t, err)
	require.Empty(t, results, "expected no Beyla self-instrumentation events")
}
