package attributes

import (
	attributes2 "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
)

// TODO : remove
type (
	Getter[T, O any]       = attributes2.Getter[T, O]
	Field[T, O any]        = attributes2.Field[T, O]
	NamedGetters[T, O any] = attributes2.NamedGetters[T, O]
)

func PrometheusGetters[T, O any](getter NamedGetters[T, O], names []attr.Name) []Field[T, O] {
	return buildGetterList[T, O](getter, names, attr.Name.Prom)
}

// OpenTelemetryGetters builds a list of Getter getters for the names provided by the
// user configuration, ready to be passed to an OpenTelemetry exporter.
func OpenTelemetryGetters[T, O any](getter NamedGetters[T, O], names []attr.Name) []Field[T, O] {
	return buildGetterList[T, O](getter, names, func(name attr.Name) string {
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
