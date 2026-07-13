// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package obi // import "go.opentelemetry.io/obi/pkg/obi"

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/helpers"
)

// Minimum required Kernel version: 5.8 (or 4.18 for RHEL-based distros)
const (
	minKernMaj, minKernMin         = 5, 8
	minRHELKernMaj, minRHELKernMin = 4, 18
)

var kernelVersion = ebpfcommon.KernelVersion

var rhelIDs = []string{"rhel", "centos", "rocky", "alma"}

func parseOSReleaseIsRHEL(data []byte) bool {
	content := strings.ToLower(string(data))
	for _, line := range strings.Split(content, "\n") {
		var val string
		switch {
		case strings.HasPrefix(line, "id_like="):
			val = line[len("id_like="):]
		case strings.HasPrefix(line, "id="):
			val = line[len("id="):]
		default:
			continue
		}
		val = strings.Trim(val, `"'`)
		for _, id := range rhelIDs {
			if strings.Contains(val, id) {
				return true
			}
		}
	}
	return false
}

// Matches RHEL release tag (.elN) or rebuilt RHEL kernels via the gcc banner.
var rhelKernelRE = regexp.MustCompile(`\.el\d+(_\d+)?\b|\(Red Hat \d+\.\d+\.\d+-\d+\)`)

func parseProcVersionIsRHEL(data []byte) bool {
	return rhelKernelRE.Match(data)
}

var isRHELBased = func() bool {
	if data, err := os.ReadFile("/etc/os-release"); err == nil && parseOSReleaseIsRHEL(data) {
		return true
	}
	if data, err := os.ReadFile("/proc/version"); err == nil && parseProcVersionIsRHEL(data) {
		return true
	}
	return false
}

// hasBTF checks whether the kernel exposes BTF information by looking for the
// vmlinux BTF file in the canonical sysfs location and fallback paths (mirroring
// libbpf's btf__load_vmlinux_btf).
var hasBTF = func() bool {
	// canonical sysfs location
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		return true
	}

	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return false
	}
	release := unix.ByteSliceToString(uname.Release[:])

	// fallback locations from libbpf
	for _, pattern := range []string{
		"/boot/vmlinux-%s",
		"/lib/modules/%s/vmlinux-%[1]s",
		"/lib/modules/%s/build/vmlinux",
		"/usr/lib/modules/%s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/boot/vmlinux-%s.debug",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
	} {
		path := fmt.Sprintf(pattern, release)
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

// checkOSSupport contains the actual logic; tests call it directly.
func checkOSSupport() error {
	major, minor := kernelVersion()
	general := major > minKernMaj || (major == minKernMaj && minor >= minKernMin)
	// RHEL relaxation only applies at the 4.18 floor.
	rhel418 := major == minRHELKernMaj && minor == minRHELKernMin && isRHELBased()
	if !general && !rhel418 {
		return fmt.Errorf("kernel version %d.%d not supported. Minimum required version is %d.%d",
			major, minor, minKernMaj, minKernMin)
	}

	if !hasBTF() {
		return errors.New("kernel does not support BTF (CONFIG_DEBUG_INFO_BTF): no vmlinux BTF found")
	}

	return nil
}

// CheckOSSupport returns an error if the running operating system does not support
// the minimum required OBI features.
// The result is cached after the first call.
var CheckOSSupport = sync.OnceValue(checkOSSupport)

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
			testAndSet(caps, capError, unix.CAP_PERFMON)
		case EbpfSourceTC:
			testAndSet(caps, capError, unix.CAP_PERFMON)
			testAndSet(caps, capError, unix.CAP_NET_ADMIN)
		}
	}

	// Note: these should be the minimum caps needed to run statsolly right now.
	// As metrics are added in the future, this list may change depending on
	// the probe used to calculate the metric.
	if config.Enabled(FeatureStatsO11y) {
		testAndSet(caps, capError, unix.CAP_SYS_PTRACE)
		testAndSet(caps, capError, unix.CAP_PERFMON)
		testAndSet(caps, capError, unix.CAP_NET_RAW)
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
