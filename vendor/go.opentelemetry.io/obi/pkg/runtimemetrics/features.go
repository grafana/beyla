// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics // import "go.opentelemetry.io/obi/pkg/runtimemetrics"

import "go.opentelemetry.io/obi/pkg/appolly/app/svc"

type FeatureSet interface {
	AppRuntime() bool
	AppJVM() bool
}

type Enabled struct {
	Go  bool
	JVM bool
}

func EnabledFeatures(features FeatureSet) Enabled {
	return Enabled{
		Go:  features.AppRuntime(),
		JVM: features.AppJVM(),
	}
}

func (e Enabled) Any() bool {
	return e.Go || e.JVM
}

func (e Enabled) ShouldReport(snapshot RuntimeMetricSnapshot) bool {
	if snapshot.Go != nil {
		return e.Go && snapshot.Service.SDKLanguage == svc.InstrumentableGolang
	}
	if snapshot.JVM != nil {
		return e.JVM &&
			snapshot.Service.ExportModes.CanExportMetrics() &&
			snapshot.Service.Features.AppJVM()
	}
	return false
}
