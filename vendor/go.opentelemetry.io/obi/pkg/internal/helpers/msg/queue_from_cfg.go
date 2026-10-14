// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package msg // import "go.opentelemetry.io/obi/pkg/internal/helpers/msg"

import (
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// QueueFromConfig creates a standard msg.Queue[T] from the given OBI config.
// The reporter receives the queue buffer utilization of every subscriber.
// It accepts a nil reporter because some callers build a global.ContextInfo
// without a Metrics reporter; those queues keep the default no-op gauge.
func QueueFromConfig[T any](
	config *obi.Config,
	metrics imetrics.Reporter,
	name string,
	overrideQueueOpts ...msg.QueueOpts,
) *msg.Queue[T] {
	queueOpts := []msg.QueueOpts{
		msg.ChannelBufferLen(config.ChannelBufferLen),
		msg.SendTimeout(config.ChannelSendTimeout),
		msg.Name(name),
	}
	if metrics != nil {
		queueOpts = append(queueOpts, msg.InternalMetrics(metrics))
	}
	if config.ChannelSendTimeoutPanic {
		queueOpts = append(queueOpts, msg.PanicOnSendTimeout())
	}
	queueOpts = append(queueOpts, overrideQueueOpts...)

	return msg.NewQueue[T](queueOpts...)
}
