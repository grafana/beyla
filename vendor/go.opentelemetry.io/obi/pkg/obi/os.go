// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package obi

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/helpers"
)

// Minimum required Kernel version: 4.18
const minKernMaj, minKernMin = 4, 18

var kernelVersion = ebpfcommon.KernelVersion

func KernelVersion() (major, minor int) {
	return kernelVersion()
}

// CheckOSSupport returns an error if the running operating system does not support
// the minimum required Beyla features.
func CheckOSSupport() error {
	major, minor := kernelVersion()
	if major < minKernMaj || (major == minKernMaj && minor < minKernMin) {
		return fmt.Errorf("kernel version %d.%d not supported. Minimum required version is %d.%d",
			major, minor, minKernMaj, minKernMin)
	}
	return nil
}

type osCapabilitiesError uint64

func (e *osCapabilitiesError) Set(c helpers.OSCapability) {
	*e |= 1 << c
}

func (e *osCapabilitiesError) Clear(c helpers.OSCapability) {
	*e &= ^(1 << c)
}

func (e osCapabilitiesError) IsSet(c helpers.OSCapability) bool {
	return e&(1<<c) > 0
}

func (e osCapabilitiesError) Empty() bool {
	return e == 0
}

func (e osCapabilitiesError) Error() string {
	if e == 0 {
		return ""
	}

	var sb strings.Builder

	sb.WriteString("the following capabilities are required: ")

	sep := ""

	for i := helpers.OSCapability(0); i <= unix.CAP_LAST_CAP; i++ {
		if e.IsSet(i) {
			sb.WriteString(sep)
			sb.WriteString(i.String())

			sep = ", "
		}
	}

	return sb.String()
}

func testAndSet(caps *helpers.OSCapabilities, capError *osCapabilitiesError, c helpers.OSCapability) {
	if !caps.Has(c) {
		capError.Set(c)
	}
}

func checkCapabilitiesForSetOptions(config *Config, caps *helpers.OSCapabilities, capError *osCapabilitiesError) {
	if config.Enabled(FeatureAppO11y) {
		testAndSet(caps, capError, unix.CAP_CHECKPOINT_RESTORE)
		testAndSet(caps, capError, unix.CAP_DAC_READ_SEARCH)
		testAndSet(caps, capError, unix.CAP_SYS_PTRACE)
		testAndSet(caps, capError, unix.CAP_PERFMON)
		testAndSet(caps, capError, unix.CAP_NET_RAW)

		if config.EBPF.ContextPropagation.IsEnabled() {
			testAndSet(caps, capError, unix.CAP_NET_ADMIN)
		}
	}

	if config.Enabled(FeatureNetO11y) {
		switch config.NetworkFlows.Source {
		case EbpfSourceSock:
			testAndSet(caps, capError, unix.CAP_NET_RAW)
		case EbpfSourceTC:
			testAndSet(caps, capError, unix.CAP_PERFMON)
			testAndSet(caps, capError, unix.CAP_NET_ADMIN)
		}
	}
}

func CheckOSCapabilities(config *Config) error {
	caps, err := helpers.GetCurrentProcCapabilities()
	if err != nil {
		return fmt.Errorf("unable to query OS capabilities: %w", err)
	}

	var capError osCapabilitiesError

	major, minor := kernelVersion()

	// below kernels 5.8 all BPF permissions were bundled under SYS_ADMIN
	if (major == 5 && minor < 8) || (major < 5) {
		testAndSet(caps, &capError, unix.CAP_SYS_ADMIN)

		if capError.Empty() {
			return nil
		}

		return capError
	}

	// if sys admin is set, we have all capabilities
	if caps.Has(unix.CAP_SYS_ADMIN) {
		return nil
	}

	// core capabilities
	testAndSet(caps, &capError, unix.CAP_BPF)

	// CAP_SYS_RESOURCE is only required on kernels < 5.11
	if (major == 5 && minor < 11) || (major < 5) {
		testAndSet(caps, &capError, unix.CAP_SYS_RESOURCE)
	}

	checkCapabilitiesForSetOptions(config, caps, &capError)

	if capError.Empty() {
		return nil
	}

	return capError
}
