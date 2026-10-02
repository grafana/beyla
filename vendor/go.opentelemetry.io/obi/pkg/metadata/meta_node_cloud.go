// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

func otelNodeFetcher(clusterKind NodeFeatures, detector resource.Detector) fetcher {
	log := slog.With("component", "meta.NodeMeta.otelNodeFetcher",
		"detector", fmt.Sprintf("%T", detector)[1:])

	return func(ctx context.Context) (NodeMeta, error) {
		// we expect very short response time in a cloud environment
		ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
		defer cancel()
		// running asynchronously to avoid that any connection issue blocks the main goroutine
		resCh := make(chan *resource.Resource, 1)
		go func() {
			for {
				select {
				case <-ctx.Done():
					// timeout! exit
					return
				default:
					// keep going
				}
				res, err := detector.Detect(ctx)
				if errors.Is(err, resource.ErrPartialResource) {
					// retry until timeout
					continue
				}
				// none of the other errors from the detector are retriable, so we just log them.
				if err != nil {
					log.Debug("can't detect Cloud metadata", "error", err)
				}
				resCh <- res
				return
			}
		}()

		var resource *resource.Resource
		select {
		case resource = <-resCh:
			if resource == nil || resource.Len() == 0 {
				// everything is fine, we might have asked for a Cloud resource from a baremetal machine
				return NodeMeta{}, nil
			}
		case <-ctx.Done():
			log.Warn("timed out while waiting for Cloud metadata. Ignoring")
			return NodeMeta{}, nil
		}

		log.Info("detected Cloud metadata")
		attrs := resource.Iter()
		store := NodeMeta{Features: clusterKind, Metadata: make([]Entry, 0, attrs.Len())}
		for attrs.Next() {
			at := attrs.Attribute()
			switch at.Key {
			case semconv.HostIDKey:
				store.HostID = at.Value.Emit()
				continue
				// TODO: add cluster names from other cloud providers
			case semconv.AWSECSClusterARNKey:
				store.Cluster = at.Value.AsString()
			case semconv.CloudRegionKey:
				store.Region = at.Value.AsString()
			}
			store.Metadata = append(store.Metadata,
				Entry{Key: attr.Name(at.Key), Value: at.Value.Emit()})
		}
		log.Debug("cloud metadata", "metadata", fmt.Sprintf("%+v", store))
		return store, nil
	}
}
