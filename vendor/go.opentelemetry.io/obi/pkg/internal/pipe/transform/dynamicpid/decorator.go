// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dynamicpid // import "go.opentelemetry.io/obi/pkg/internal/pipe/transform/dynamicpid"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/selection"
)

func log() *slog.Logger { return slog.With("component", "dynamicpid.MetadataDecorator") }

// MetadataDecoratorProvider applies service identity and resource attributes from a dynamic PID
// selector to flow records whose source or destination IP belongs to a selected application.
func MetadataDecoratorProvider[T any](
	multiSel selection.MultiSignalPIDSelector,
	signalSel selection.PIDSelector,
	k8sInformer *kube.MetadataProvider,
	getAttrs func(T) *pipe.CommonAttrs,
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(instantiateCtx context.Context) (swarm.RunFunc, error) {
		if multiSel == nil {
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
		tracker := selection.NewDynamicFlowAttrs(multiSel, signalSel, store)
		in := input.Subscribe(msg.SubscriberName("dynamicpid.MetadataDecorator"))
		return func(ctx context.Context) {
			tracker.Run(ctx)
			defer output.Close()
			swarms.ForEachInput(ctx, in, log().Debug, func(items []T) {
				for _, item := range items {
					tracker.Apply(getAttrs(item))
				}
				output.Send(items)
			})
		}, nil
	}
}
