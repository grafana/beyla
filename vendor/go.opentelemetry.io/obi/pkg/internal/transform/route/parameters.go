// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package route // import "go.opentelemetry.io/obi/pkg/internal/transform/route"

import "strings"

func validRoute(parts []string) bool {
	for i, part := range parts {
		if tail, ok := routeParam(part); ok && tail && i != len(parts)-1 {
			return false
		}
	}
	return true
}

// Parameters used to be handled by a simple regexp.MustCompile(`^((:\w*)|(\{\w*}))$`).
// Flask uses angled brackets <> for declarations and this is how OpenTelemetry Python SDK
// reports them. We could've just extended the above with | <>, but Flask and FastAPI also
// support the {name:path} annotation, where path consumes the rest of the path, e.g.
// # FastAPI: matches /files/a/b/c.txt
// @app.get("/files/{file_path:path}")

// # Flask: matches /files/a/b/c.txt
// @app.route("/files/<path:file_path>")
func routeParam(part string) (bool, bool) {
	if part == "*" {
		return true, true
	}
	if strings.HasPrefix(part, ":") {
		return false, validParamName(part[1:])
	}
	if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
		name := part[1 : len(part)-1]
		tail := strings.HasPrefix(name, "*")
		if tail {
			name = strings.TrimPrefix(name, "*")
			name = strings.TrimPrefix(name, "*")
		}
		name, conv, found := strings.Cut(name, ":")
		if !found {
			name, _, _ = strings.Cut(name, "=")
			name = strings.TrimSuffix(name, "?")
		}
		if !validParamName(name) || found && !validConverter(conv) {
			return false, false
		}
		return tail || found && converterName(conv) == "path", true
	}
	if strings.HasPrefix(part, "<") && strings.HasSuffix(part, ">") {
		conv, name, found := strings.Cut(part[1:len(part)-1], ":")
		if !found {
			name = conv
			conv = ""
		}
		if !validParamName(name) || found && !validConverter(conv) {
			return false, false
		}
		return found && converterName(conv) == "path", true
	}
	return false, false
}

func validParamName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

func validConverter(conv string) bool {
	return conv != "" && !strings.ContainsAny(conv, `/<>{}`)
}

func converterName(conv string) string {
	name, _, _ := strings.Cut(conv, "(")
	return name
}
