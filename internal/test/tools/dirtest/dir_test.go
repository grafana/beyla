package testutil

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/internal/test/tools"
)

// Unorthodox way to provide another test case to ../dir.go: we are testing
// that the relative path still works when invoked from another directory depth
func TestProjectDir(t *testing.T) {
	prjDir := tools.ProjectDir()
	// Test that the project relative dir is correct by checking for the
	// existence of a file that should be only placed in the project
	// root (e.g. third_party_licenses.csv)
	fi, err := os.Stat(path.Join(prjDir, "third_party_licenses.csv"))
	require.NoError(t, err)
	require.NotNil(t, fi)
	assert.NotEmpty(t, fi.Name())
}
