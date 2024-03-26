package beyla

import (
	"fmt"

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
