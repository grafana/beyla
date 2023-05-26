package ebpf

import (
	"github.com/cilium/ebpf"
)

// placeholder to avoid Darwin linter and unit tests to fail

func attachSocketFilter(_ *ebpf.Program) (int, error) {
	return 0, nil
}
