package beyla

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/helpers"
)

// Minimum required Kernel version: 5.8
const minKernMaj, minKernMin = 5, 8

var kernelVersion = ebpfcommon.KernelVersion

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

	sep := ""

	for i := helpers.OSCapability(0); i <= unix.CAP_LAST_CAP; i++ {
		if e.IsSet(i) {
			sb.WriteString(sep)
			sb.WriteString(i.String())

			sep = ", "
		}
	}

	return fmt.Sprintf("the following capabilities are required: %s", sb.String())
}

func CheckOSCapabilities(config *Config) error {
	caps, err := helpers.GetCurrentProcCapabilities()

	if err != nil {
		return fmt.Errorf("unable to query OS capabilities: %w", err)
	}

	var capError osCapabilitiesError

	testAndSet := func(c helpers.OSCapability) {
		if !caps.Has(c) {
			capError.Set(c)
		}
	}

	// core capabilities
	testAndSet(unix.CAP_BPF)
	testAndSet(unix.CAP_PERFMON)
	testAndSet(unix.CAP_DAC_READ_SEARCH)

	major, minor := kernelVersion()

	// CAP_SYS_RESOURCE is only required on kernels < 5.11
	if (major == 5 && minor < 11) || (major < 5) {
		testAndSet(unix.CAP_SYS_RESOURCE)
	}

	if config.Enabled(FeatureAppO11y) {
		testAndSet(unix.CAP_CHECKPOINT_RESTORE)
		testAndSet(unix.CAP_SYS_PTRACE)
	}

	if config.Enabled(FeatureNetO11y) {
		testAndSet(unix.CAP_NET_RAW)
	}

	if capError.Empty() {
		return nil
	}

	return capError
}
