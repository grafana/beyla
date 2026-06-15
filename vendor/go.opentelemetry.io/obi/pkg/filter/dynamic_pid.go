// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package filter // import "go.opentelemetry.io/obi/pkg/filter"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/selection"
)

// ByDynamicPID provides a pipeline node that keeps only records whose source or destination IP
// belongs to a dynamically selected application (via DynamicPIDSelector). When the selector is nil,
// the node is bypassed.
func ByDynamicPID[T any](
	selector selection.PIDSelector,
	k8sInformer *kube.MetadataProvider,
	attrs func(T) *pipe.CommonAttrs,
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(instantiateCtx context.Context) (swarm.RunFunc, error) {
		if selector == nil {
			return swarm.Bypass(input, output)
		}
		var store *kube.Store
		if k8sInformer != nil && k8sInformer.IsKubeEnabled() {
			var err error
			store, err = k8sInformer.Get(instantiateCtx)
			if err != nil {
				return nil, err
			}
		}
		tracker := selection.NewDynamicAppIPs(selector, store)
		in := input.Subscribe(msg.SubscriberName("filter.ByDynamicPID"))
		return func(loopCtx context.Context) {
			tracker.Run(loopCtx)
			defer output.Close()
			swarms.ForEachInput(loopCtx, in, nil, func(items []T) {
				out := filterByDynamicPID(items, attrs, tracker)
				if len(out) > 0 {
					output.SendCtx(loopCtx, out)
				}
			})
		}, nil
	}
}

func filterByDynamicPID[T any](items []T, attrs func(T) *pipe.CommonAttrs, tracker *selection.DynamicAppIPs) []T {
	writeIdx := 0
	for readIdx := range items {
		if tracker.Allows(attrs(items[readIdx])) {
			items[writeIdx] = items[readIdx]
			writeIdx++
		}
	}
	return items[:writeIdx]
}
