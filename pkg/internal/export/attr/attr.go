package attr

import (
	"strings"
)

// GetFunc is a function that explains how to get a given metric attribute from a data record
// of the generic type T (e.g. *ebpf.Record or *request.Span)
type GetFunc[T any] func(T) string

// Getter stores how to expose a metric attribute: its exposed name and how to
// get its value from the data record of type T
type Getter[T any] struct {
	// ExposedName of a metric will vary between OTEL and Prometheus: dot.notation or underscore_notation.
	ExposedName string
	Get         GetFunc[T]
}

// NamedGetters returns the GetFunc for an attribute, given its internal name in dot.notation.
type NamedGetters[T any] func(internalName string) GetFunc[T]

// PrometheusGetters builds a list of GetFunc getters for the names provided by the
// user configuration, ready to be passed to a Prometheus exporter.
// It differentiates two name formats: the exposed name for the attribute (uses _ for word separation, as
// required by Prometheus); and the internal name of the attribute (uses . for word separation, as internally Beyla
// stores the metadata).
// Whatever is the format provided by the user (dot-based or underscore-based), it converts dots to underscores
// and vice-versa to make sure that the correct format is used either internally or externally.
func PrometheusGetters[T any](getter NamedGetters[T], names []string) []Getter[T] {
	attrs := make([]Getter[T], 0, len(names))
	for _, name := range names {
		exposedName := normalizeToUnderscore(name)
		internalName := strings.ReplaceAll(name, "_", ".")
		attrs = append(attrs, Getter[T]{
			ExposedName: exposedName,
			Get:         getter(internalName),
		})
	}
	return attrs
}

// OpenTelemetryGetters builds a list of GetFunc getters for the names provided by the
// user configuration, ready to be passed to an OpenTelemetry exporter.
// Whatever is the format of the user-provided attribute names (dot-based or underscore-based),
// it converts underscores to dots to make sure that the correct attribute name is exposed.
func OpenTelemetryGetters[T any](getter NamedGetters[T], names []string) []Getter[T] {
	attrs := make([]Getter[T], 0, len(names))
	for _, name := range names {
		dotName := normalizeToDot(name)
		attrs = append(attrs, Getter[T]{
			ExposedName: dotName,
			Get:         getter(dotName),
		})
	}
	return attrs
}

func normalizeToUnderscore(name string) string {
	return strings.ReplaceAll(name, ".", "_")
}

// normalizeToDot will have into account that some dot metrics still have underscores,
// such as: http.response.status_code
// The name is provided by the user, so this function will handle mistakes in the dot
// or underscore notation from the user
func normalizeToDot(name string) string {
	name = strings.ReplaceAll(name, "_", ".")
	// TODO: add future edge cases here
	// nolint:gocritic
	switch name {
	case "http.response.status.code":
		name = "http.response.status_code"
	}
	return name
}
