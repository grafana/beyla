// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package flow

import (
	"context"
	"errors"
	"log/slog"
	"time"

	ebpfcommon "go.opentelemetry.io/obi/pkg/components/ebpf/common"
	"go.opentelemetry.io/obi/pkg/components/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

func rtlog() *slog.Logger {
	return slog.With("component", "flow.RingBufTracer")
}

// RingBufTracer receives single-packet flows via ringbuffer (usually, these that couldn't be
// added in the eBPF kernel space due to the map being full or busy) and submits them to the
// userspace Aggregator map
type RingBufTracer struct {
	ringBuffer    ringBufReader
	flushInterval time.Duration
}

type ringBufReader interface {
	ReadInto(*ringbuf.Record) error
}

func NewRingBufTracer(reader ringBufReader, flushInterval time.Duration) *RingBufTracer {
	return &RingBufTracer{
		ringBuffer:    reader,
		flushInterval: flushInterval,
	}
}

func (m *RingBufTracer) TraceLoop(out *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
	return func(ctx context.Context) {
		defer out.MarkCloseable()
		rtlog := rtlog()

		var rec ringbuf.Record

		ticker := time.NewTicker(m.flushInterval)
		defer ticker.Stop()

		// this serves as a buffer to be able to batch enqueue flows into the output queue.
		// queue channel sizes may not scale well and enqueue operations can be quite expensive
		// given this is a very high throughput path, we start with a 1MB buffer, which will
		// increase automatically if necessary - use OTEL_EBPF_NETWORK_SAMPLING to properly control
		// event throughput and the memory pressure
		flows := make([]*ebpf.Record, 0, 1048576)

		for {
			select {
			case <-ctx.Done():
				rtlog.Debug("exiting trace loop due to context cancellation")
				return
			case <-ticker.C:
				if len(flows) > 0 {
					out.Send(append([]*ebpf.Record(nil), flows...))

					// this ensures the buffer is recycled / no reallocs
					flows = flows[:0]
				}
			default:
				if err := m.ringBuffer.ReadInto(&rec); err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						rtlog.Debug("Received signal, exiting..")
						return
					}

					rtlog.Warn("ignoring flow event", "error", err)
					continue
				}

				event, err := ebpfcommon.ReinterpretCast[ebpf.NetFlowRecordT](rec.RawSample)
				if err != nil {
					continue
				}

				flows = append(flows, &ebpf.Record{NetFlowRecordT: *event})
			}
		}
	}
}
