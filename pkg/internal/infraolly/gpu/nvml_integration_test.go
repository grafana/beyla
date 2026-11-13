//go:build linux && beyla_nvml && integration

package gpu

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// A child process lets the dynamic loader read LD_LIBRARY_PATH at startup and
// isolates NVML's process-wide state from other tests and installed drivers.
func TestNVMLIntegration(t *testing.T) {
	if os.Getenv("BEYLA_NVML_TEST_CHILD") == "1" {
		devices, err := discoverNVIDIA()
		if os.Getenv("BEYLA_NVML_FAIL_INIT") == "1" {
			require.ErrorContains(t, err, "fixture error")
			return
		}
		require.NoError(t, err)
		defer shutdownNVIDIA()
		require.Len(t, devices, 1)
		require.Equal(t, "GPU-fixture", devices[0].Info().ID)
		require.Equal(t, "Fixture GPU", devices[0].Info().Name)
		sample, err := devices[0].Sample()
		require.NoError(t, err)
		require.Equal(t, ptr(0.42), sample.Utilization)
		require.Equal(t, ptr(0.17), sample.MemoryControllerUtilization)
		require.Equal(t, ptr(int64(4096)), sample.MemoryLimitBytes)
		require.Equal(t, ptr(int64(1024)), sample.MemoryUsedBytes)
		require.Equal(t, ptr(125.0), sample.PowerWatts)
		require.Nil(t, sample.FanSpeedRatio)
		require.Nil(t, sample.EnergyJoules)
		return
	}
	dir := t.TempDir()
	output, err := exec.Command("cc", "-shared", "-fPIC", "-o", filepath.Join(dir, "libnvidia-ml.so.1"), "testdata/nvml.c").CombinedOutput()
	require.NoError(t, err, "%s", output)
	executable, err := os.Executable()
	require.NoError(t, err)
	for _, fail := range []string{"0", "1"} {
		t.Run("init_failure_"+fail, func(t *testing.T) {
			cmd := exec.Command(executable, "-test.run=^TestNVMLIntegration$", "-test.v")
			cmd.Env = append(os.Environ(), "LD_LIBRARY_PATH="+dir, "BEYLA_NVML_TEST_CHILD=1", "BEYLA_NVML_FAIL_INIT="+fail)
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "%s", output)
		})
	}
}
