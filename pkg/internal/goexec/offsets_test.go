package goexec

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/export/otel"
	"github.com/grafana/beyla/pkg/internal/testutil"
)

// TestProcessNotFound tests that InspectOffsets process exits on context cancellation
// even if the target process wasn't found
func TestProcessNotFound(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	cancel()
	finish := make(chan struct{})
	go func() {
		defer close(finish)
		cfg := &otel.TracesConfig{}
		_, err := InspectOffsets(cfg, nil, nil)
		require.Error(t, err)
	}()
	testutil.ReadChannel(t, finish, 5*time.Second)
}
