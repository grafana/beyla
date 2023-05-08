package goexec

import (
	"context"
	"testing"
	"time"

	"github.com/grafana/ebpf-autoinstrument/pkg/testutil"

	"github.com/shirou/gopsutil/process"
	"github.com/stretchr/testify/require"
)

// TestProcessNotFound tests that InspectOffsets process exits on context cancellation
// even if the target process wasn't found
func TestProcessNotFound(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	finish := make(chan struct{})
	go func() {
		defer close(finish)
		_, err := InspectOffsets(ctx, func() (*process.Process, bool) {
			return nil, false
		}, nil)
		require.Error(t, err)
	}()
	testutil.ReadChannel(t, finish, 5*time.Second)
}
