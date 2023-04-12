//go:build integration

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/docker"
)

func TestSuite(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", "../../test-suite.log")
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	defer func() {
		require.NoError(t, compose.Close())
	}()
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
}

// Same as Test suite, but the generated test image does not contain debug information
func TestSuite_NoDebugInfo(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", "../../test-suite-nodebug.log")
	compose.Env = append(compose.Env, `TESTSERVER_DOCKERFILE_SUFFIX=_nodebug`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	defer func() {
		require.NoError(t, compose.Close())
	}()
	t.Run("RED metrics", testREDMetricsHTTP)
	// No GRPC tests for now, until we fix the offsets lookup
}
