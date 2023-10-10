package integration

import (
	"os"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// prerequisite: the testoutput/run folder was empty before starting the tests
func testBPFPinningMountedWithCount(t *testing.T, expectedCount int) {
	entries, err := os.ReadDir(pathVarRun)
	require.NoError(t, err)
	require.Lenf(t, entries, expectedCount,
		"if the %s folder contained more than one entry, "+
			"it might be that the previous tests weren't correctly "+
			"cleaned up. Try removing the folder and run the test again", pathVarRun)
}

func testBPFPinningMounted(t *testing.T) {
	testBPFPinningMountedWithCount(t, 1)
}

// to be invoked after docker compose down
func testBPFPinningUnmounted(t *testing.T) {
	entries, err := os.ReadDir(pathVarRun)
	require.NoError(t, err)
	require.Empty(t, entries)

	// Convenient hook for monitoring storage space:
	PrintStorage(t)
	PrintDockerStorage(t)
}

func PrintStorage(t *testing.T) {
	// Convenient hook for monitoring storage space:
	var stat unix.Statfs_t
	wd, err := os.Getwd()
	if err == nil && unix.Statfs(wd, &stat) == nil {
		t.Logf("Free storage space (in %s) is: %dMB\n", wd, stat.Bavail*uint64(stat.Bsize)/(1024*1024))
	}
}

func PrintDockerStorage(t *testing.T) {
	out, err := exec.Command("docker", "system", "df").CombinedOutput()
	if err == nil {
		t.Logf("Docker system df output:\n%s", string(out))
	}
}
