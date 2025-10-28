// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package svc

import (
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
)

type InstrumentableType int

const (
	InstrumentableGolang InstrumentableType = iota + 1
	InstrumentableJava
	InstrumentableJavaNative
	InstrumentableDotnet
	InstrumentablePython
	InstrumentableRuby
	InstrumentableNodejs
	InstrumentableRust
	InstrumentableGeneric
	InstrumentablePHP
)

func (it InstrumentableType) String() string {
	switch it {
	case InstrumentableGolang:
		return semconv.TelemetrySDKLanguageGo.Value.AsString()
	case InstrumentableJava, InstrumentableJavaNative:
		return semconv.TelemetrySDKLanguageJava.Value.AsString()
	case InstrumentableDotnet:
		return semconv.TelemetrySDKLanguageDotnet.Value.AsString()
	case InstrumentablePython:
		return semconv.TelemetrySDKLanguagePython.Value.AsString()
	case InstrumentableRuby:
		return semconv.TelemetrySDKLanguageRuby.Value.AsString()
	case InstrumentableNodejs:
		return semconv.TelemetrySDKLanguageNodejs.Value.AsString()
	case InstrumentableRust:
		return semconv.TelemetrySDKLanguageRust.Value.AsString()
	case InstrumentablePHP:
		return semconv.TelemetrySDKLanguagePHP.Value.AsString()
	case InstrumentableGeneric:
		return "generic"
	default:
		// if this appears, it's a bug!!
		return "unknown"
	}
}

type idFlags uint8

const (
	autoName               idFlags = 0x1
	exportsOTelMetrics     idFlags = 0x2
	exportsOTelTraces      idFlags = 0x4
	exportsOTelMetricsSpan idFlags = 0x8
)

type ServiceNameNamespace struct {
	Name      string
	Namespace string
}

func (sn ServiceNameNamespace) String() string {
	return sn.Namespace + "/" + sn.Name
}

// UID uniquely identifies a service instance across the whole system
// according to the OpenTelemetry specification: (name, namespace, instance)
type UID struct {
	Name      string
	Namespace string
	Instance  string
}

func (uid *UID) NameNamespace() ServiceNameNamespace {
	return ServiceNameNamespace{Name: uid.Name, Namespace: uid.Namespace}
}

func (uid *UID) Equals(other *UID) bool {
	return uid.Name == other.Name && uid.Namespace == other.Namespace && uid.Instance == other.Instance
}

// Attrs stores the metadata attributes of a service/resource
type Attrs struct {
	// Instance uniquely identifies a service instance. It is not exported
	// in the metrics or traces, but it is used to compose the Instance
	UID UID

	SDKLanguage InstrumentableType

	Metadata map[attr.Name]string

	// ProcPID is the PID of the instrumented process as seen by Beyla's /proc filesystem.
	// It is stored here at process discovery time, because it might differ form the
	// UserPID and HostPID fields of the request.PidInfo struct.
	ProcPID int32

	// HostName running the process. It will default to the Beyla host and will be overridden
	// by other metadata if available (e.g., Pod Name, Node Name, etc...)
	HostName string

	EnvVars map[string]string

	flags idFlags

	ExportModes services.ExportModes

	Sampler trace.Sampler

	CustomInRouteMatcher  route.Matcher
	CustomOutRouteMatcher route.Matcher
	HarvestedRouteMatcher route.Matcher
}

func (i *Attrs) GetUID() UID {
	return i.UID
}

func (i *Attrs) String() string {
	return i.Job()
}

func (i *Attrs) Job() string {
	if i.UID.Namespace != "" {
		return i.UID.Namespace + "/" + i.UID.Name
	}
	return i.UID.Name
}

func (i *Attrs) setFlag(flag idFlags) {
	i.flags |= flag
}

func (i *Attrs) getFlag(flag idFlags) bool {
	return (i.flags & flag) == flag
}

func (i *Attrs) SetAutoName() {
	i.setFlag(autoName)
}

func (i *Attrs) AutoName() bool {
	return i.getFlag(autoName)
}

func (i *Attrs) SetExportsOTelMetrics() {
	i.setFlag(exportsOTelMetrics)
}

func (i *Attrs) ExportsOTelMetrics() bool {
	return i.getFlag(exportsOTelMetrics)
}

func (i *Attrs) SetExportsOTelMetricsSpan() {
	i.setFlag(exportsOTelMetricsSpan)
}

func (i *Attrs) ExportsOTelMetricsSpan() bool {
	return i.getFlag(exportsOTelMetricsSpan)
}

func (i *Attrs) SetExportsOTelTraces() {
	i.setFlag(exportsOTelTraces)
}

func (i *Attrs) ExportsOTelTraces() bool {
	return i.getFlag(exportsOTelTraces)
}

func (i *Attrs) SetHarvestedRoutes(matcher route.Matcher) {
	i.HarvestedRouteMatcher = matcher
}

func (i *Attrs) SetCustomRoutes(config *services.CustomRoutesConfig) {
	i.CustomInRouteMatcher = route.NewMatcher(config.Incoming)
	i.CustomOutRouteMatcher = route.NewMatcher(config.Outgoing)
}
