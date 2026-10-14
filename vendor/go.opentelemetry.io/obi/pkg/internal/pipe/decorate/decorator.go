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

package decorate // import "go.opentelemetry.io/obi/pkg/internal/pipe/decorate"

import (
	"context"
	"net"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

// Decorate the items with extra metadata fields that are not directly fetched by eBPF
// or by any previous pipeline stage (DNS, Kubernetes...):
//   - The IP address of the agent host.
//   - If there is no source or destination hostname, the source IP and destination
//     names are filled with their respective IP string values.
func Decorate[T any](agentIP net.IP, attrs func(T) *pipe.CommonAttrs, input, output *msg.Queue[[]T]) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		ip := agentIP.String()
		in := input.Subscribe(msg.SubscriberName("decorate.Decorate"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, nil, func(items []T) {
				for _, item := range items {
					a := attrs(item)
					a.OBIIP = ip
					if a.DstName == "" {
						a.DstName = a.DstAddr.IP().String()
					}
					if a.SrcName == "" {
						a.SrcName = a.SrcAddr.IP().String()
					}
				}
				output.Send(items)
			})
		}, nil
	}
}
