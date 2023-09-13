package tools

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectDir(t *testing.T) {
	prjDir := ProjectDir()
	// Test that the project relative dir is correct by checking for the
	// existence of a file that should be only placed in the project
	// root (e.g. third_party_licenses.csv)
	fi, err := os.Stat(path.Join(prjDir, "third_party_licenses.csv"))
	require.NoError(t, err)
	require.NotNil(t, fi)
	assert.NotEmpty(t, fi.Name())
}
