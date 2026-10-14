// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

// HTTPMethodOther is the semconv http.request.method value for a method outside
// the enum.
var HTTPMethodOther = semconv.HTTPRequestMethodOther.Value.AsString()

// Semconv mandates this variable name for overriding the enum: a comma-separated
// list replacing the defaults below.
const envKnownMethods = "OTEL_INSTRUMENTATION_HTTP_KNOWN_METHODS"

// Taken from the semconv enum members rather than copied as literals, so a
// changed value fails to compile instead of silently clamping a valid method.
// Method names are case-sensitive, so the set is matched exactly.
var defaultKnownHTTPMethods = methodSet(
	semconv.HTTPRequestMethodConnect,
	semconv.HTTPRequestMethodDelete,
	semconv.HTTPRequestMethodGet,
	semconv.HTTPRequestMethodHead,
	semconv.HTTPRequestMethodOptions,
	semconv.HTTPRequestMethodPatch,
	semconv.HTTPRequestMethodPost,
	semconv.HTTPRequestMethodPut,
	semconv.HTTPRequestMethodQuery,
	semconv.HTTPRequestMethodTrace,
)

func methodSet(members ...attribute.KeyValue) map[string]struct{} {
	set := make(map[string]struct{}, len(members))
	for _, m := range members {
		set[m.Value.AsString()] = struct{}{}
	}

	return set
}

// parseKnownHTTPMethods reads the override list, falling back to the semconv
// defaults when it is unset or contains no usable entry.
func parseKnownHTTPMethods(env string) map[string]struct{} {
	if strings.TrimSpace(env) == "" {
		return defaultKnownHTTPMethods
	}

	methods := map[string]struct{}{}
	for m := range strings.SplitSeq(env, ",") {
		if m = strings.TrimSpace(m); m != "" {
			methods[m] = struct{}{}
		}
	}

	if len(methods) == 0 {
		return defaultKnownHTTPMethods
	}

	return methods
}

var knownHTTPMethods = sync.OnceValue(func() map[string]struct{} {
	return parseKnownHTTPMethods(os.Getenv(envKnownMethods))
})

// IsKnownHTTPMethod reports whether method is a member of the semconv
// http.request.method enum, honoring the override. Both the trace and metric
// pipelines clamp through this so they cannot disagree on the same attribute key.
func IsKnownHTTPMethod(method string) bool {
	_, ok := knownHTTPMethods()[method]
	return ok
}
