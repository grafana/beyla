//go:build linux

package beyla

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/grafana/beyla/v2/pkg/config"
	"github.com/grafana/beyla/v2/pkg/internal/helpers"
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
		{maj: 4, min: 0},
		{maj: 4, min: 17},
	} {
		t.Run(fmt.Sprintf("%d.%d", tc.maj, tc.min), func(t *testing.T) {
			overrideKernelVersion(tc)
			assert.Error(t, CheckOSSupport())
		})
	}
}

func TestOSCapabilitiesError_Empty(t *testing.T) {
	var capErr osCapabilitiesError

	assert.True(t, capErr.Empty())
	assert.Equal(t, "", capErr.Error())
}

func TestOSCapabilitiesError_Set(t *testing.T) {
	var capErr osCapabilitiesError

	for c := helpers.OSCapability(0); c <= unix.CAP_LAST_CAP; c++ {
		assert.False(t, capErr.IsSet(c))
		capErr.Set(c)
		assert.True(t, capErr.IsSet(c))
		capErr.Clear(c)
		assert.False(t, capErr.IsSet(c))
	}
}

func TestOSCapabilitiesError_ErrorString(t *testing.T) {
	var capErr osCapabilitiesError

	assert.Equal(t, "", capErr.Error())

	capErr.Set(unix.CAP_BPF)

	// no separator (,)
	assert.Equal(t, "the following capabilities are required: CAP_BPF", capErr.Error())

	capErr.Set(unix.CAP_NET_RAW)

	// capabilities appear in ascending order (they are just numeric
	// constants) separated by a comma
	assert.True(t, unix.CAP_NET_RAW < unix.CAP_BPF)
	assert.Equal(t, "the following capabilities are required: CAP_NET_RAW, CAP_BPF", capErr.Error())
}

type capClass int

const (
	capCore = capClass(iota + 1)
	capApp
	capNet
)

type capTestData struct {
	osCap   helpers.OSCapability
	class   capClass
	kernMaj int
	kernMin int
	useTC   bool
}

var capTests = []capTestData{
	// core
	{osCap: unix.CAP_BPF, class: capCore, kernMaj: 6, kernMin: 10, useTC: false},

	// app o11y
	{osCap: unix.CAP_CHECKPOINT_RESTORE, class: capApp, kernMaj: 6, kernMin: 10, useTC: false},
	{osCap: unix.CAP_DAC_READ_SEARCH, class: capApp, kernMaj: 6, kernMin: 10, useTC: false},
	{osCap: unix.CAP_SYS_PTRACE, class: capApp, kernMaj: 6, kernMin: 10, useTC: false},
	{osCap: unix.CAP_PERFMON, class: capApp, kernMaj: 6, kernMin: 10, useTC: false},
	{osCap: unix.CAP_NET_RAW, class: capApp, kernMaj: 6, kernMin: 10, useTC: false},
	{osCap: unix.CAP_NET_ADMIN, class: capApp, kernMaj: 6, kernMin: 10, useTC: true},

	// net o11y
	{osCap: unix.CAP_NET_RAW, class: capNet, kernMaj: 6, kernMin: 10, useTC: false},
	{osCap: unix.CAP_PERFMON, class: capNet, kernMaj: 6, kernMin: 10, useTC: true},
	{osCap: unix.CAP_NET_ADMIN, class: capNet, kernMaj: 6, kernMin: 10, useTC: true},
}

func TestCheckOSCapabilities(t *testing.T) {
	caps, err := helpers.GetCurrentProcCapabilities()

	assert.NoError(t, err)

	// assume this proc doesn't have any caps set (which is usually the case
	// for non privileged processes) instead of turning this into a privileged
	// test and manually dropping capabilities
	assert.Zero(t, caps[0].Effective)
	assert.Zero(t, caps[1].Effective)

	test := func(data *capTestData) {
		overrideKernelVersion(testCase{data.kernMaj, data.kernMin})

		netSource := func(useTC bool) string {
			if useTC {
				return EbpfSourceTC
			}

			return EbpfSourceSock
		}

		cfg := Config{
			NetworkFlows: NetworkConfig{Enable: data.class == capNet, Source: netSource(data.useTC)},
			EBPF:         config.EBPFTracer{ContextPropagationEnabled: data.useTC},
		}
		if data.class == capApp {
			// activates app o11y feature
			require.NoError(t, cfg.Exec.UnmarshalText([]byte(".")))
		}

		err := CheckOSCapabilities(&cfg)

		if !assert.Error(t, err) {
			assert.FailNow(t, "CheckOSCapabilities() should have returned an error")
		}

		var osCapErr osCapabilitiesError

		if !errors.As(err, &osCapErr) {
			assert.Fail(t, "CheckOSCapabilities failed", err)
		}

		assert.True(t, osCapErr.IsSet(data.osCap),
			fmt.Sprintf("%s should be present in error", data.osCap.String()))
	}

	for i := range capTests {
		c := capTests[i]
		t.Run(fmt.Sprintf("%s %d.%d", c.osCap.String(), c.kernMaj, c.kernMin), func(*testing.T) {
			test(&c)
		})
	}
}
