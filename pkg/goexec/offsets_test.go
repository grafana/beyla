package goexec

import (
	"context"
	"testing"
	"time"

	"github.com/grafana/ebpf-autoinstrument/pkg/testutil"

	"github.com/stretchr/testify/require"
)

// TestProcessNotFound tests that InspectOffsets process exits on context cancellation
// even if the target process wasn't found
func TestProcessNotFound(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	cancel()
	finish := make(chan struct{})
	go func() {
		defer close(finish)
		_, err := InspectOffsets(nil, nil)
		require.Error(t, err)
	}()
	testutil.ReadChannel(t, finish, 5*time.Second)
}
