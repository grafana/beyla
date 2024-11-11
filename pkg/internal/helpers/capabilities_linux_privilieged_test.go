//go:build linux

package helpers

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

const privilegedEnv = "PRIVILEGED_TESTS"

var expectedProcCaps *OSCapabilities
var errResetCaps error

// This needs to run in the main thread (called by TestMain() below)
// capset() can fail with EPERM when called from a different thread. From the
// manpage:
//
//	EPERM  The caller attempted to use capset() to modify the capabilities of
//	a thread other than itself, but lacked sufficient privilege.  For kernels
//	supporting VFS capabilities, this is never  permitted.
//	For  kernels  lacking  VFS  support,  the CAP_SETPCAP  capability  is  required.
//
// We need to drop capabilities to correctly test TestCheckOSCapabilities()
func resetProcCapabilities() {
	var err error

	expectedProcCaps, err = GetCurrentProcCapabilities()

	errRef := &err
	cleanup := func() {
		if *errRef != nil {
			errResetCaps = fmt.Errorf("failed to reset capabilities: %w", *errRef)
		}
	}

	defer cleanup()

	if err != nil {
		return
	}

	expectedProcCaps.Clear(unix.CAP_BPF)
	expectedProcCaps.Set(unix.CAP_BPF)

	err = SetCurrentProcCapabilities(expectedProcCaps)
}

func TestGetSetCurrentProcCaps(t *testing.T) {
	if os.Getenv(privilegedEnv) == "" {
		t.Skipf("Set %s to run this test\n", privilegedEnv)
	}

	if errResetCaps != nil {
		assert.Fail(t, errResetCaps.Error())
	}

	caps, err := GetCurrentProcCapabilities()
	assert.NoError(t, err)
	assert.Equal(t, expectedProcCaps, caps)
}

func TestMain(m *testing.M) {
	if os.Getenv(privilegedEnv) != "" {
		resetProcCapabilities()
	}

	os.Exit(m.Run())
}
