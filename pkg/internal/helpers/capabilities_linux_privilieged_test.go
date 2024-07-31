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
func resetProcCapabilities() error {
	var err error

	expectedProcCaps, err = GetCurrentProcCapabilities()

	if err != nil {
		return err
	}

	expectedProcCaps.Clear(unix.CAP_BPF)
	expectedProcCaps.Set(unix.CAP_BPF)

	return SetCurrentProcCapabilities(expectedProcCaps)
}

func TestGetSetCurrentProcCaps(t *testing.T) {
	caps, err := GetCurrentProcCapabilities()
	assert.NoError(t, err)
	assert.Equal(t, expectedProcCaps, caps)
}

func TestMain(m *testing.M) {
	if os.Getenv(privilegedEnv) == "" {
		fmt.Printf("Set %s to run this test\n", privilegedEnv)
		os.Exit(0)
	}

	if err := resetProcCapabilities(); err != nil {
		fmt.Printf("Failed to reset capabilities: %s\n", err)
		os.Exit(-1)
	}

	os.Exit(m.Run())
}
