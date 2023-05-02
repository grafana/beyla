//go:build integration

package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grafana/ebpf-autoinstrument/test/integration/components/docker"
)

func TestSuite(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", "../../testoutput/test-suite.log")
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
	compose, err := docker.ComposeSuite("docker-compose.yml", "../../testoutput/test-suite-nodebug.log")
	compose.Env = append(compose.Env, `TESTSERVER_DOCKERFILE_SUFFIX=_nodebug`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	defer func() {
		require.NoError(t, compose.Close())
	}()
	t.Run("RED metrics", testREDMetricsHTTP)
	t.Run("GRPC RED metrics", testREDMetricsGRPC)
}

// Same as Test suite, but searching the executable by port instead of executable name
func TestSuite_OpenPort(t *testing.T) {
	compose, err := docker.ComposeSuite("docker-compose.yml", "../../testoutput/test-suite-openport.log")
	compose.Env = append(compose.Env, `OPEN_PORT=8080`, `EXECUTABLE_NAME=""`)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	defer func() {
		require.NoError(t, compose.Close())
	}()
	t.Run("RED metrics", testREDMetricsHTTP)
}
