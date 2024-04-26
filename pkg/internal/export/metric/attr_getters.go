package metric

import (
	"strings"
)

// Getter is a function that defines how to get a given metric attribute of the type
// O (e.g. string or attribute.KeyValue) from a data record
// of the generic type T (e.g. *ebpf.Record or *request.Span)
type Getter[T, O any] func(T) O

// Field stores how to expose a metric attribute: its exposed name and how to
// get its O-typed value from the data record of type T
type Field[T, O any] struct {
	// ExposedName of a metric will vary between OTEL and Prometheus: dot.notation or underscore_notation.
	ExposedName string
	Get         Getter[T, O]
}

// NamedGetters returns the Getter for an attribute, given its internal name in dot.notation.
// If the record does not provide any value for the given name, the second argument is false.
type NamedGetters[T, O any] func(internalName string) (Getter[T, O], bool)

// PrometheusGetters builds a list of Getter getters for the names provided by the
// user configuration, ready to be passed to a Prometheus exporter.
// It differentiates two name formats: the exposed name for the attribute (uses _ for word separation, as
// required by Prometheus); and the internal name of the attribute (uses . for word separation, as internally Beyla
// stores the metadata).
// Whatever is the format provided by the user (dot-based or underscore-based), it converts dots to underscores
// and vice-versa to make sure that the correct format is used either internally or externally.
func PrometheusGetters[T, O any](getter NamedGetters[T, O], names []string) []Field[T, O] {
	attrs := make([]Field[T, O], 0, len(names))
	for _, name := range names {
		exposedName := normalizeToUnderscore(name)
		internalName := strings.ReplaceAll(name, "_", ".")
		if get, ok := getter(internalName); ok {
			attrs = append(attrs, Field[T, O]{
				ExposedName: exposedName,
				Get:         get,
			})
		}
	}
	return attrs
}

// OpenTelemetryGetters builds a list of Getter getters for the names provided by the
// user configuration, ready to be passed to an OpenTelemetry exporter.
// Whatever is the format of the user-provided attribute names (dot-based or underscore-based),
// it converts underscores to dots to make sure that the correct attribute name is exposed.
func OpenTelemetryGetters[T, O any](getter NamedGetters[T, O], names []string) []Field[T, O] {
	attrs := make([]Field[T, O], 0, len(names))
	for _, name := range names {
		dotName := NormalizeToDot(name)
		if get, ok := getter(dotName); ok {
			attrs = append(attrs, Field[T, O]{
				ExposedName: dotName,
				Get:         get,
			})
		}
	}
	return attrs
}

func normalizeToUnderscore(name string) string {
	return strings.ReplaceAll(name, ".", "_")
}

// NormalizeToDot will have into account that some dot metrics still have underscores,
// such as: http.response.status_code
// The name is provided by the user, so this function will handle mistakes in the dot
// or underscore notation from the user
func NormalizeToDot(name string) string {
	return strings.ReplaceAll(name, "_", ".")
}
