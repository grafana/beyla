// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics // import "go.opentelemetry.io/obi/pkg/export/imetrics"

import (
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

const DynamicInvocationDescription = "Function entry probe hits since dynamic probe attachment"

// DynamicProbeCounter reads a live attachment, independently of span export.
// Service must return a concurrency-safe snapshot, including late metadata updates.
type DynamicProbeCounter struct {
	PID      int
	Function string
	Service  func() svc.Attrs
	Read     func() (uint64, error)
}

type dynamicCounterState struct {
	probe         DynamicProbeCounter
	start         time.Time
	previousTime  time.Time
	previousCount uint64
}

type DynamicProbeSample struct {
	Attributes attribute.Set
	Count      uint64
	StartTime  time.Time
	Time       time.Time
}

// DynamicProbeCounters retains only live attachments. A new attachment ID starts
// a fresh counter even when its PID and function match a removed probe.
type DynamicProbeCounters struct {
	mu     sync.Mutex
	probes map[uint64]*dynamicCounterState
}

// DynamicProbeInvocations registers or updates an attachment; nil removes it.
func (p *DynamicProbeCounters) DynamicProbeInvocations(id uint64, probe *DynamicProbeCounter) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if probe == nil {
		delete(p.probes, id)
		return
	}
	if p.probes == nil {
		p.probes = map[uint64]*dynamicCounterState{}
	}
	if state := p.probes[id]; state != nil {
		state.probe = *probe
	} else {
		p.probes[id] = &dynamicCounterState{probe: *probe, start: time.Now()}
	}
}

func (p *DynamicProbeCounters) CollectDynamicProbes(delta bool) []DynamicProbeSample {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	samples := make([]DynamicProbeSample, 0, len(p.probes))
	for id, state := range p.probes {
		count, err := state.probe.Read()
		if err != nil {
			// A concurrently detached map entry must not look like a counter reset.
			continue
		}
		attrs := dynamicProbeAttributes(id, &state.probe)
		sample := DynamicProbeSample{Attributes: attrs, Count: count, StartTime: state.start, Time: now}
		if delta && !state.previousTime.IsZero() && count >= state.previousCount {
			sample.Count -= state.previousCount
			sample.StartTime = state.previousTime
		}
		state.previousTime = now
		state.previousCount = count
		samples = append(samples, sample)
	}
	return samples
}

func dynamicProbeLabelNames() []attr.Name {
	labels := []attr.Name{
		attr.Name(attr.VendorPrefix + ".dynamic.probe.id"), "process.pid", "code.function.name", attr.ServiceName, attr.ServiceNamespace,
		attr.ServiceInstanceID, attr.TelemetrySDKLanguage, attr.HostName,
		attr.ContainerID, attr.ContainerName,
	}
	return append(labels, attributes.KubernetesTargetInfoAttributes()...)
}

func dynamicProbeAttributes(id uint64, probe *DynamicProbeCounter) attribute.Set {
	service := probe.Service()
	values := []attribute.KeyValue{
		attribute.String(attr.VendorPrefix+".dynamic.probe.id", strconv.FormatUint(id, 10)),
		attribute.Int("process.pid", probe.PID),
		attribute.String("code.function.name", attributes.SanitizeUTF8(probe.Function)),
		attr.ServiceName.OTEL().String(attributes.SanitizeUTF8(service.UID.Name)),
		attr.ServiceNamespace.OTEL().String(attributes.SanitizeUTF8(service.UID.Namespace)),
		attr.ServiceInstanceID.OTEL().String(attributes.SanitizeUTF8(service.UID.Instance)),
		attr.TelemetrySDKLanguage.OTEL().String(service.SDKLanguage.String()),
		attr.HostName.OTEL().String(attributes.SanitizeUTF8(service.HostName)),
	}
	for _, name := range append([]attr.Name{attr.ContainerID, attr.ContainerName}, attributes.KubernetesTargetInfoAttributes()...) {
		if value := service.Metadata[name]; value != "" {
			values = append(values, name.OTEL().String(attributes.SanitizeUTF8(value)))
		}
	}
	return attribute.NewSet(values...)
}
