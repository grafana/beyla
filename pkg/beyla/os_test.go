package beyla

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

type testCase struct {
	maj int
	min int
}

var overrideKernelVersion = func(tc testCase) {
	kernelVersion = func() (major, minor int) {
		return tc.maj, tc.min
	}
}

func TestCheckOSSupport_Supported(t *testing.T) {
	for _, tc := range []testCase{
		{maj: 5, min: 8},
		{maj: 6, min: 0},
		{maj: 7, min: 15},
	} {
		t.Run(fmt.Sprintf("%d.%d", tc.maj, tc.min), func(t *testing.T) {
			overrideKernelVersion(tc)
			assert.NoError(t, CheckOSSupport())
		})
	}
}

func TestCheckOSSupport_Unsupported(t *testing.T) {
	for _, tc := range []testCase{
		{maj: 0, min: 0},
		{maj: 3, min: 11},
		{maj: 5, min: 0},
		{maj: 5, min: 7},
	} {
		t.Run(fmt.Sprintf("%d.%d", tc.maj, tc.min), func(t *testing.T) {
			overrideKernelVersion(tc)
			assert.Error(t, CheckOSSupport())
		})
	}
}

var capTests = []capDesc{
	{osCap: unix.CAP_BPF, str: "CAP_BPF"},
	{osCap: unix.CAP_CHECKPOINT_RESTORE, str: "CAP_CHECKPOINT_RESTORE"},
	{osCap: unix.CAP_DAC_READ_SEARCH, str: "CAP_DAC_READ_SEARCH"},
	{osCap: unix.CAP_NET_RAW, str: "CAP_NET_RAW"},
	{osCap: unix.CAP_PERFMON, str: "CAP_PERFMON"},
	{osCap: unix.CAP_SYS_PTRACE, str: "CAP_SYS_PTRACE"},
	{osCap: unix.CAP_SYS_RESOURCE, str: "CAP_SYS_RESOURCE", kernMaj: 5, kernMin: 10},
	{osCap: unix.CAP_SYS_RESOURCE, str: "CAP_SYS_RESOURCE", kernMaj: 4, kernMin: 11},
}

func TestOSCapability_String(t *testing.T) {
	test := func(c *capDesc) {
		t.Run(c.str, func(t *testing.T) {
			assert.Equal(t, c.osCap.String(), c.str)
		})
	}

	for i := range capTests {
		test(&capTests[i])
	}

	capEmpty := capDesc{osCap: 0, str: "UNKNOWN"}
	capInv := capDesc{osCap: 99, str: "UNKNOWN"}

	test(&capEmpty)
	test(&capInv)
}

func TestOSCapabilitiesError_Empty(t *testing.T) {
	var capErr osCapabilitiesError

	assert.True(t, capErr.Empty())
	assert.Equal(t, capErr.Error(), "")
}

func TestOSCapabilitiesError_Set(t *testing.T) {
	var capErr osCapabilitiesError

	for i := range capTests {
		c := capTests[i].osCap

		assert.False(t, capErr.IsSet(c))
		capErr.Set(c)
		assert.True(t, capErr.IsSet(c))
		capErr.Clear(c)
		assert.False(t, capErr.IsSet(c))
	}
}

func TestOSCapabilitiesError_ErrorString(t *testing.T) {
	var capErr osCapabilitiesError

	assert.Equal(t, capErr.Error(), "")

	capErr.Set(unix.CAP_BPF)

	// no separator (,)
	assert.Equal(t, capErr.Error(), "the following capabilities are required: CAP_BPF")

	capErr.Set(unix.CAP_NET_RAW)

	// capabilities appear in ascending order (they are just numeric
	// constants) separated by a comma
	assert.True(t, unix.CAP_NET_RAW < unix.CAP_BPF)
	assert.Equal(t, capErr.Error(), "the following capabilities are required: CAP_NET_RAW, CAP_BPF")
}

func TestCheckOSCapabilities_capData(t *testing.T) {
	var data capUserData

	assert.Zero(t, data[0])
	assert.Zero(t, data[1])

	setCap(&data, unix.CAP_BPF)

	assert.True(t, isCapSet(&data, unix.CAP_BPF))

	unsetCap(&data, unix.CAP_BPF)

	assert.False(t, isCapSet(&data, unix.CAP_BPF))
}

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
func dropCapabilities() error {
	data, err := getCurrentProcCapabilities()

	if err != nil {
		return err
	}

	for i := range capTests {
		unsetCap(data, capTests[i].osCap)
	}

	return setCurrentProcCapabilities(data)
}

func TestCheckOSCapabilities(t *testing.T) {
	test := func(data *capDesc) {
		overrideKernelVersion(testCase{data.kernMaj, data.kernMin})

		err := CheckOSCapabilities()

		if !assert.Error(t, err) {
			assert.FailNow(t, "CheckOSCapabilities() should have returned an error")
		}

		var osCapErr osCapabilitiesError

		if !errors.As(err, &osCapErr) {
			assert.Fail(t, "CheckOSCapabilities failed", err)
		}

		assert.True(t, osCapErr.IsSet(data.osCap),
			fmt.Sprintf("%s should be present in error", data.str))
	}

	for i := range capTests {
		c := capTests[i]
		t.Run(fmt.Sprintf("%s %d.%d", c.osCap.String(), c.kernMaj, c.kernMin), func(*testing.T) {
			test(&c)
		})
	}
}

func TestMain(m *testing.M) {
	if err := dropCapabilities(); err != nil {
		fmt.Printf("Failed to drop capabilities: %s\n", err)
		os.Exit(-1)
	}

	os.Exit(m.Run())
}
