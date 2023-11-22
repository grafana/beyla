package ebpfcommon

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func setIntegrity(path, text string) {
	os.WriteFile(path, []byte(text), 0644)
}

func setNotReadable(path string) {
	os.Chmod(path, 000)
}

func TestLockdownParsing(t *testing.T) {
	noFile, err := os.CreateTemp("", "not_existent_fake_lockdown")
	assert.NoError(t, err)
	notPath, err := filepath.Abs(noFile.Name())
	assert.NoError(t, err)
	noFile.Close()
	os.Remove(noFile.Name())

	// Setup for testing file that doesn't exist
	lockdownPath = notPath
	assert.Equal(t, KernelLockdownNone, KernelLockdownMode())

	tempFile, err := os.CreateTemp("", "fake_lockdown")
	assert.NoError(t, err)
	path, err := filepath.Abs(tempFile.Name())
	assert.NoError(t, err)
	tempFile.Close()

	defer os.Remove(tempFile.Name())
	// Setup for testing
	lockdownPath = path

	setIntegrity(path, "none [integrity] confidentiality\n")
	assert.Equal(t, KernelLockdownIntegrity, KernelLockdownMode())

	setIntegrity(path, "[none] integrity confidentiality\n")
	assert.Equal(t, KernelLockdownNone, KernelLockdownMode())

	setIntegrity(path, "none integrity [confidentiality]\n")
	assert.Equal(t, KernelLockdownConfidentiality, KernelLockdownMode())

	setIntegrity(path, "whatever\n")
	assert.Equal(t, KernelLockdownOther, KernelLockdownMode())

	setIntegrity(path, "")
	assert.Equal(t, KernelLockdownIntegrity, KernelLockdownMode())

	setIntegrity(path, "[none] integrity confidentiality\n")
	setNotReadable(path)
	assert.Equal(t, KernelLockdownIntegrity, KernelLockdownMode())
}
