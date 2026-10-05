// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import "go.opentelemetry.io/obi/pkg/runtimemetrics"

type runtimeCollection struct {
	gc      gcRound
	polling runtimemetrics.DotnetRuntimeMetricSnapshot
}

func (c *runtimeCollection) observe(counter runtimeCounter) (*runtimemetrics.DotnetRuntimeMetricSnapshot, error) {
	// System.Runtime polls working-set before the other supported counters.
	if c.polling.ProcessMemoryWorkingSet == nil && counter.Name != "working-set" {
		return nil, nil
	}
	var completed *runtimemetrics.DotnetRuntimeMetricSnapshot
	if counter.Name == "working-set" && c.polling.ProcessMemoryWorkingSet != nil {
		if c.polling.GCCollections[0] != nil {
			snapshot := c.polling
			completed = &snapshot
		}
		c.polling = runtimemetrics.DotnetRuntimeMetricSnapshot{}
	}
	if err := observePollingCounter(&c.polling, counter); err != nil {
		return nil, err
	}
	gcSnapshot, err := c.gc.observe(counter)
	if err != nil {
		return nil, err
	}
	if gcSnapshot != nil {
		c.polling.GCCollections = gcSnapshot.GCCollections
	}
	return completed, nil
}

func (c *runtimeCollection) finish() *runtimemetrics.DotnetRuntimeMetricSnapshot {
	// assembly-count is the last supported counter in the runtime's polling order.
	if c.polling.AssemblyCount == nil || c.polling.GCCollections[0] == nil {
		return nil
	}
	snapshot := c.polling
	c.polling = runtimemetrics.DotnetRuntimeMetricSnapshot{}
	return &snapshot
}
