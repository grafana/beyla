// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen // import "go.opentelemetry.io/obi/pkg/export/otel/tracesgen"

import (
	"net/url"
	"strings"
)

// Returns nil when keys is empty so callers can short-circuit cheaply.
func buildRedactSet(keys []string) map[string]struct{} {
	if len(keys) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[k] = struct{}{}
	}
	return set
}

// Returns qs unchanged when redactSet is nil/empty or qs is empty.
func scrubQuery(qs string, redactSet map[string]struct{}) string {
	if len(redactSet) == 0 || qs == "" {
		return qs
	}

	var b strings.Builder
	b.Grow(len(qs))

	rest := qs
	for rest != "" {
		part := rest
		if i := strings.IndexByte(rest, '&'); i >= 0 {
			part, rest = rest[:i], rest[i+1:]
		} else {
			rest = ""
		}

		key, val, hasVal := strings.Cut(part, "=")
		if !hasVal {
			b.WriteString(part)
		} else {
			b.WriteString(key)
			b.WriteByte('=')
			// Percent-decode the key so ?X-Amz-Signatur%65=v is caught alongside
			// ?X-Amz-Signature=v. The raw key is preserved in the output; only the value
			// is replaced. url.QueryUnescape returns the input string unchanged (no
			// allocation) when no percent-sequences are present.
			lookupKey := key
			if decoded, err := url.QueryUnescape(key); err == nil {
				lookupKey = decoded
			}
			if _, isSensitive := redactSet[lookupKey]; isSensitive {
				b.WriteString("REDACTED")
			} else {
				b.WriteString(val)
			}
		}

		if rest != "" {
			b.WriteByte('&')
		}
	}

	return b.String()
}
