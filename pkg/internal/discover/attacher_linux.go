package discover

import (
	"fmt"

	"github.com/cilium/ebpf/rlimit"
)

func (ta *TraceAttacher) close() {
}

func (ta *TraceAttacher) init() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memory lock: %w", err)
	}
	return nil
}
