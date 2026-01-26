// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package msg // import "go.opentelemetry.io/obi/pkg/internal/helpers/msg"

import (
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// QueueFromConfig creates a standard msg.Queue[T] from the given OBI config
func QueueFromConfig[T any](config *obi.Config, name string, overrideQueueOpts ...msg.QueueOpts) *msg.Queue[T] {
	queueOpts := []msg.QueueOpts{
		msg.ChannelBufferLen(config.ChannelBufferLen),
		msg.SendTimeout(config.ChannelSendTimeout),
		msg.Name(name),
	}
	if config.ChannelSendTimeoutPanic {
		queueOpts = append(queueOpts, msg.PanicOnSendTimeout())
	}
	queueOpts = append(queueOpts, overrideQueueOpts...)

	return msg.NewQueue[T](queueOpts...)
}
