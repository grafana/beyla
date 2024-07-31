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

type capDesc struct {
	osCap helpers.OSCapability
	str   string

	// kernMaj.kernMin is the MAXIMUM kernel version this capability is needed
	// if push comes to shove in the future, we may want to implement proper
	// ranges here
	kernMaj int
	kernMin int
}

var requiredCaps = []capDesc{
	{osCap: unix.CAP_BPF, str: "CAP_BPF"},
	{osCap: unix.CAP_CHECKPOINT_RESTORE, str: "CAP_CHECKPOINT_RESTORE"},
	{osCap: unix.CAP_DAC_READ_SEARCH, str: "CAP_DAC_READ_SEARCH"},
	{osCap: unix.CAP_NET_RAW, str: "CAP_NET_RAW"},
	{osCap: unix.CAP_PERFMON, str: "CAP_PERFMON"},
	{osCap: unix.CAP_SYS_PTRACE, str: "CAP_SYS_PTRACE"},
	{osCap: unix.CAP_SYS_RESOURCE, str: "CAP_SYS_RESOURCE", kernMaj: 5, kernMin: 10},
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

func CheckOSCapabilities() error {
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

	major, minor := kernelVersion()

	for i := range requiredCaps {
		c := &requiredCaps[i]

		if c.kernMaj == 0 ||
			(major == c.kernMaj && minor <= c.kernMin) ||
			(major < c.kernMaj) {
			testAndSet(c.osCap)
		}
	}

	if capError.Empty() {
		return nil
	}

	return capError
}
