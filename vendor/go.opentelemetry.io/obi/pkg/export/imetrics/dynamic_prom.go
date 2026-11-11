// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics // import "go.opentelemetry.io/obi/pkg/export/imetrics"

import "github.com/prometheus/client_golang/prometheus"

type dynamicInvocationCollector struct {
	counters *DynamicProbeCounters
	desc     *prometheus.Desc
}

func newDynamicInvocationCollector(counters *DynamicProbeCounters, name string) *dynamicInvocationCollector {
	var labels []string
	for _, name := range dynamicProbeLabelNames() {
		labels = append(labels, name.Prom())
	}
	return &dynamicInvocationCollector{counters: counters, desc: prometheus.NewDesc(name, DynamicInvocationDescription, labels, nil)}
}

func (p *dynamicInvocationCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- p.desc
}

func (p *dynamicInvocationCollector) Collect(ch chan<- prometheus.Metric) {
	for _, sample := range p.counters.CollectDynamicProbes(false) {
		var values []string
		for _, name := range dynamicProbeLabelNames() {
			value, ok := sample.Attributes.Value(name.OTEL())
			if ok {
				values = append(values, value.Emit())
			} else {
				values = append(values, "")
			}
		}
		ch <- prometheus.MustNewConstMetric(p.desc, prometheus.CounterValue, float64(sample.Count), values...)
	}
}
