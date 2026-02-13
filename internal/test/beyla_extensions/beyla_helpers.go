//go:build ignore

// Beyla-specific test helpers
// This file is copied to internal/testgenerated/integration/ by generate-obi-tests.sh

package integration

import (
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/require"

	obipkg "go.opentelemetry.io/obi/pkg/obi"
	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v3/internal/testgenerated/integration/components/promtest"
)

// testConfig returns the Beyla-specific test configuration used by integration
// tests that call into the OBI test library (e.g. InternalPrometheusExport).
func testConfig() *ti.TestConfig {
	return &ti.TestConfig{
		EnvPrefix:          "BEYLA_",
		ComposeServiceName: "autoinstrumenter",
		ComposeImageName:   "hatest-autoinstrumenter",
		DockerfilePath:     "beyla/Dockerfile",
		ConfigPath:         "beyla-config.yml",
		MetricPrefix:       "beyla",
		IPAttribute:        "beyla.ip",
		SDKName:            "beyla",
		VersionPkg:         "buildinfo.Version",
	}
}

// kprobeTracesEnabled returns true if the kernel version is high enough to
// support kprobe-based distributed traces (>= 5.17).
func kprobeTracesEnabled() bool {
	major, minor := obipkg.KernelVersion()

	return major > 5 || (major == 5 && minor >= 17)
}

// waitForSQLTestComponents waits for SQL test components with the default
// PostgreSQL database backend.
func waitForSQLTestComponents(t *testing.T, url, subpath string) {
	waitForSQLTestComponentsWithDB(t, url, subpath, "postgresql")
}

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
