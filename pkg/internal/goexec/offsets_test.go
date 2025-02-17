package goexec

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/internal/testutil"
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
