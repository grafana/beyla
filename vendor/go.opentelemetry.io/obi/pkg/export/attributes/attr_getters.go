// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import attr "go.opentelemetry.io/obi/pkg/export/attributes/names"

// Getter is a function that defines how to get a given metric attribute of the type O
// (e.g. string or attribute.KeyValue) from a data record
// of the generic type T (e.g. *ebpf.Record or *request.Span)
type Getter[T, O any] func(T) O

// Field stores how to expose a metric attribute: its exposed name and how to
// get its O-typed value from the data record of type T
type Field[T, O any] struct {
	// ExposedName of a metric will vary between OTEL and Prometheus: dot.notation or underscore_notation.
	ExposedName string
	Get         Getter[T, O]
}

// NamedGetters returns the Getter for an attribute, given its internal name representation.
// If the record does not provide any value for the given name, the second argument is false.
type NamedGetters[T, O any] func(name attr.Name) (Getter[T, O], bool)

// PrometheusGetters builds a list of Getter getters for the names provided by the
// user configuration, ready to be passed to a Prometheus exporter.
// It differentiates two name formats: the exposed name for the attribute (uses _ for word separation, as
// required by Prometheus); and the internal name of the attribute (uses . for word separation, as internally Beyla
// stores the metadata).
func PrometheusGetters[T, O any](getter NamedGetters[T, O], names []attr.Name) []Field[T, O] {
	return buildGetterList(getter, names, attr.Name.Prom)
}

// OpenTelemetryGetters builds a list of Getter getters for the names provided by the
// user configuration, ready to be passed to an OpenTelemetry exporter.
func OpenTelemetryGetters[T, O any](getter NamedGetters[T, O], names []attr.Name) []Field[T, O] {
	return buildGetterList(getter, names, func(name attr.Name) string {
		return string(name.OTEL())
	})
}

func buildGetterList[T, O any](
	getter NamedGetters[T, O],
	names []attr.Name,
	exposedNamer func(attr.Name) string,
) []Field[T, O] {
	attrs := make([]Field[T, O], 0, len(names))
	for _, name := range names {
		if get, ok := getter(name); ok {
			attrs = append(attrs, Field[T, O]{
				ExposedName: exposedNamer(name),
				Get:         get,
			})
		}
	}
	return attrs
}
