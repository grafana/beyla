//go:build beyla_extension

// Beyla-specific integration tests for multiprocess context propagation
// This file is copied to internal/obi/test/integration/ by generate-obi-tests.sh

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v3/internal/obi/test/integration/components/docker"
)

// TestMultiProcessAppCPNoIP_Beyla is a Beyla-specific test for context propagation
// with headers only (no IP-based propagation).
// NOTE: Named with _Beyla suffix to avoid potential conflicts
func TestMultiProcessAppCPNoIP_Beyla(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose-multiexec-host.yml", path.Join(pathOutput, "test-suite-multiexec-app-cp-no-ip.log"))
	// we are going to setup discovery directly in the configuration file
	compose.Env = append(compose.Env, `BEYLA_BPF_DISABLE_BLACK_BOX_CP=1`, `BEYLA_BPF_CONTEXT_PROPAGATION=headers`, `BEYLA_BPF_TRACK_REQUEST_HEADERS=1`)

	require.NoError(t, err)
	require.NoError(t, compose.Up())

	if kprobeTracesEnabled() {
		t.Run("Nested traces with kprobes: rust -> java -> node -> go -> python -> rails", func(t *testing.T) {
			testNestedHTTPTracesKProbes(t)
		})
	}
	require.NoError(t, compose.Close())
}
