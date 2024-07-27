package beyla

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
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

type osCapability uint8

type capDesc struct {
	osCap osCapability
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

func (c osCapability) String() string {
	for i := range requiredCaps {
		if c == requiredCaps[i].osCap {
			return requiredCaps[i].str
		}
	}

	return "UNKNOWN"
}

type osCapabilitiesError uint64

func (e *osCapabilitiesError) Set(c osCapability) {
	*e |= 1 << c
}

func (e *osCapabilitiesError) Clear(c osCapability) {
	*e &= ^(1 << c)
}

func (e osCapabilitiesError) IsSet(c osCapability) bool {
	return e&(1<<c) > 0
}

func (e osCapabilitiesError) Empty() bool {
	return e == 0
}

func (e osCapabilitiesError) Error() string {
	// linux capabilities are at most a byte long in practice
	const capMax = 0xff

	if e == 0 {
		return ""
	}

	var sb strings.Builder

	sep := ""

	for i := osCapability(1); i < capMax; i++ {
		if e.IsSet(i) {
			sb.WriteString(sep)
			sb.WriteString(i.String())

			sep = ", "
		}
	}

	return fmt.Sprintf("the following capabilities are required: %s", sb.String())
}

// From the capget(2) manpage:
// Note that 64-bit capabilities use datap[0] and datap[1], whereas 32-bit capabilities use only datap[0].
type capUserData [2]unix.CapUserData

func capUserHeader() *unix.CapUserHeader {
	return &unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     int32(os.Getpid()),
	}
}

func getCurrentProcCapabilities() (*capUserData, error) {
	data := capUserData{}

	err := unix.Capget(capUserHeader(), &data[0])

	return &data, err
}

// used by tests
func setCurrentProcCapabilities(data *capUserData) error {
	return unix.Capset(capUserHeader(), &data[0])
}

func isCapSet(data *capUserData, c osCapability) bool {
	return (data[c>>5].Effective & (1 << (c & 31))) > 0
}

// used by tests
func unsetCap(data *capUserData, c osCapability) {
	data[c>>5].Effective &= ^(1 << (c & 31))
}

// used by tests
func setCap(data *capUserData, c osCapability) {
	data[c>>5].Effective |= (1 << (c & 31))
}

func CheckOSCapabilities() error {
	data, err := getCurrentProcCapabilities()

	if err != nil {
		return fmt.Errorf("unable to query OS capabilities: %w", err)
	}

	var capError osCapabilitiesError

	testAndSet := func(c osCapability) {
		if !isCapSet(data, c) {
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
