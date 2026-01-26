// Copyright Sam Xie
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package otelsql

import (
	"net"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"
)

// AttributesFromDSN returns attributes extracted from a DSN string.
// It makes the best effort to retrieve values for [semconv.ServerAddressKey] and [semconv.ServerPortKey].
func AttributesFromDSN(dsn string) []attribute.KeyValue {
	// [scheme://][user[:password]@][protocol([addr])]/dbname[?param1=value1&paramN=valueN]
	// Find the schema part.
	schemaIndex := strings.Index(dsn, "://")
	if schemaIndex != -1 {
		// Remove the schema part from the DSN.
		dsn = dsn[schemaIndex+3:]
	}

	// [user[:password]@][protocol([addr])]/dbname[?param1=value1&paramN=valueN]
	// Find credentials part.
	atIndex := strings.Index(dsn, "@")
	if atIndex != -1 {
		// Remove the credential part from the DSN.
		dsn = dsn[atIndex+1:]
	}

	// [protocol([addr])]/dbname[?param1=value1&paramN=valueN]
	// Find the '/' that separates the address part from the database part.
	pathIndex := strings.Index(dsn, "/")
	if pathIndex != -1 {
		// Remove the path part from the DSN.
		dsn = dsn[:pathIndex]
	}

	// [protocol([addr])] or [addr]
	// Find the '(' that starts the address part.
	openParen := strings.Index(dsn, "(")
	if openParen != -1 {
		// Remove the protocol part from the DSN.
		dsn = dsn[openParen+1 : len(dsn)-1]
	}

	// [addr]
	if len(dsn) == 0 {
		return nil
	}

	host, portStr, err := net.SplitHostPort(dsn)
	if err != nil {
		host = dsn
	}

	attrs := make([]attribute.KeyValue, 0, 2)
	if host != "" {
		attrs = append(attrs, semconv.ServerAddress(host))
	}

	if portStr != "" {
		port, err := strconv.ParseInt(portStr, 10, 64)
		if err == nil {
			attrs = append(attrs, semconv.ServerPortKey.Int64(port))
		}
	}

	return attrs
}
