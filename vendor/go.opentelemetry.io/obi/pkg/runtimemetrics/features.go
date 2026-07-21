// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package runtimemetrics // import "go.opentelemetry.io/obi/pkg/runtimemetrics"

import "go.opentelemetry.io/obi/pkg/appolly/app/svc"

type FeatureSet interface {
	AppRuntime() bool
}

type Enabled struct {
	Runtime bool
}

func EnabledFeatures(features FeatureSet) Enabled {
	return Enabled{
		Runtime: features.AppRuntime(),
	}
}

func (e Enabled) Any() bool {
	return e.Runtime
}

func (e Enabled) ShouldReport(snapshot RuntimeMetricSnapshot) bool {
	if snapshot.Go != nil {
		return e.Runtime && snapshot.Service.SDKLanguage == svc.InstrumentableGolang
	}
	if snapshot.JVM != nil {
		return e.Runtime &&
			snapshot.Service.ExportModes.CanExportMetrics() &&
			snapshot.Service.Features.AppRuntime()
	}
	return false
}
