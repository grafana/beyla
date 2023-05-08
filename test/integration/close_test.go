package integration

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// prerequisite: the testoutput/run folder was empty before starting the tests
func testBPFPinningMounted(t *testing.T) {
	entries, err := os.ReadDir(pathVarRun)
	require.NoError(t, err)
	require.Lenf(t, entries, 1,
		"if the %s folder contained more than one entry, "+
			"it might be that the previous tests weren't correctly "+
			"cleaned up. Try removing the folder and run the test again", pathVarRun)
}

// to be invoked after docker compose down
func testBPFPinningUnmounted(t *testing.T) {
	entries, err := os.ReadDir(pathVarRun)
	require.NoError(t, err)
	require.Empty(t, entries)
}
