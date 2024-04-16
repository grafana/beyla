//go:build linux

package discover

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMountBpfPinPath(t *testing.T) {
	if os.Getenv(privilegedEnv) == "" {
		t.Skipf("Set %s to run this test", privilegedEnv)
	}
	tmpDir := "path"
	ta := &TraceAttacher{
		log:     slog.With("component", "discover.TraceAttacher"),
		pinPath: tmpDir,
	}

	// Nothing there to start the test
	mounted, matched, err := IsMountFS(FilesystemTypeBPFFS, tmpDir)
	assert.NoError(t, err)
	assert.False(t, mounted)
	assert.False(t, matched)

	err = ta.mountBpfPinPath()
	assert.NoError(t, err)

	// Check that it is mounted
	mounted, matched, err = IsMountFS(FilesystemTypeBPFFS, tmpDir)
	assert.NoError(t, err)
	assert.True(t, mounted)
	assert.True(t, matched)

	// Ensure mounting the same path twice does not fail
	err = ta.mountBpfPinPath()
	assert.NoError(t, err)

	// Check that it is mounted
	mounted, matched, err = IsMountFS(FilesystemTypeBPFFS, tmpDir)
	assert.NoError(t, err)
	assert.True(t, mounted)
	assert.True(t, matched)

	ta.unmountBpfPinPath()

	// Check that it is cleaned up
	mounted, matched, err = IsMountFS(FilesystemTypeBPFFS, tmpDir)
	assert.NoError(t, err)
	assert.False(t, mounted)
	assert.False(t, matched)
}
