// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package msg

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"

	"github.com/grafana/beyla/v2/pkg/internal/testutil"
)

const timeout = 5 * time.Second

func TestBasicOptions(t *testing.T) {
	logOutput := threadSafeBuffer{}

	slog.SetDefault(slog.New(slog.NewTextHandler(&logOutput, nil)))

	queue := QueueFromConfig[int](&obi.Config{
		ChannelBufferLen:   1,
		ChannelSendTimeout: 5 * time.Millisecond,
	}, "basicQueue")
	out := queue.Subscribe(msg.SubscriberName("test-out"))

	ctx, c := context.WithTimeout(t.Context(), timeout)
	defer c()
	go func() {
		// will be immediately sent due to buffer = 1
		queue.SendCtx(ctx, 123)
		// won't be immediately sent due to timeout on buffer
		go queue.SendCtx(ctx, 456)
	}()

	// wait for the blocked log to be written
	var amsg atomic.Value
	test.Eventually(t, timeout, func(t require.TestingT) {
		str, err := logOutput.ReadString('\n')
		require.NoError(t, err)
		amsg.Store(str)
	})
	require.NotNil(t, amsg.Load())
	msg := amsg.Load().(string)
	assert.Contains(t, msg, "blocked")
	assert.Contains(t, msg, "timeout=5ms")
	assert.Contains(t, msg, "queueName=basicQueue")
	assert.Contains(t, msg, "queueLen=1")
	assert.Contains(t, msg, "queueCap=1")
	assert.Contains(t, msg, "subscriber=test-out")

	// the messages are eventually delivered
	assert.Equal(t, 123, testutil.ReadChannel(t, out, timeout))
	assert.Equal(t, 456, testutil.ReadChannel(t, out, timeout))
}

func TestBasicOptions_PanicOnBlock(t *testing.T) {
	logOutput := threadSafeBuffer{}
	slog.SetDefault(slog.New(slog.NewTextHandler(&logOutput, nil)))

	queue := QueueFromConfig[int](&obi.Config{
		ChannelBufferLen:        1,
		ChannelSendTimeout:      5 * time.Millisecond,
		ChannelSendTimeoutPanic: true,
	}, "basicQueue")
	out := queue.Subscribe(msg.SubscriberName("test-out"))

	ctx, c := context.WithTimeout(t.Context(), timeout)
	defer c()
	// will be immediately sent due to buffer = 1
	sent := make(chan struct{})
	go func() {
		queue.SendCtx(ctx, 123)
		close(sent)
	}()
	testutil.ReadChannel(t, sent, timeout)
	// won't be immediately sent due to timeout on buffer
	assert.Panics(t, func() {
		queue.SendCtx(ctx, 456)
	}, "expected panic due to timeout")

	// the first message was delivered
	assert.Equal(t, 123, testutil.ReadChannel(t, out, timeout))
	// but the second message was never delivered
	testutil.ChannelEmpty(t, out, 10*time.Millisecond)
}

// avoids some race conditions between the queue and the eventually clauses
type threadSafeBuffer struct {
	mt     sync.Mutex
	buffer bytes.Buffer
}

func (t *threadSafeBuffer) Write(p []byte) (n int, err error) {
	t.mt.Lock()
	defer t.mt.Unlock()
	return t.buffer.Write(p)
}

func (t *threadSafeBuffer) ReadString(delim byte) (string, error) {
	t.mt.Lock()
	defer t.mt.Unlock()
	return t.buffer.ReadString(delim)
}
