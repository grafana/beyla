// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package request // import "go.opentelemetry.io/obi/pkg/appolly/app/request"

import (
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

type UnresolvedNames struct {
	Generic  string
	Outgoing string
	Incoming string
}

// SpanOTELGetters returns the proper attributes.NamedGetters implementation for the given
// user-provided configuration.
func SpanOTELGetters(unresolved UnresolvedNames) attributes.NamedGetters[*Span, attribute.KeyValue] {
	return otelUnresolvedHostGetters(unresolved)
}

// SpanPromGetters returns the proper attributes.NamedGetters implementation for the given
// user-provided configuration.
func SpanPromGetters(unresolved UnresolvedNames) attributes.NamedGetters[*Span, string] {
	return promUnresolvedHostGetters(unresolved)
}

var dbClientDefaultPorts = map[string]int{
	semconv.DBSystemNamePostgreSQL.Value.AsString():         5432,
	semconv.DBSystemNameMySQL.Value.AsString():              3306,
	semconv.DBSystemNameMicrosoftSQLServer.Value.AsString(): 1433,
	semconv.DBSystemNameRedis.Value.AsString():              6379,
	semconv.DBSystemNameMemcached.Value.AsString():          11211,
	semconv.DBSystemNameMongoDB.Value.AsString():            27017,
	semconv.DBSystemNameCouchbase.Value.AsString():          11210,
	"aerospike": 3000,
	semconv.DBSystemNameElasticsearch.Value.AsString(): 9200,
	semconv.DBSystemNameOpenSearch.Value.AsString():    9200,
}

// dbClientServerPortGetter implements the db.client.operation.duration semconv
// condition for server.port: report it by default only for a known port other
// than the DBMS default and only when the server address is set. When the user
// explicitly includes the attribute, any known port is reported. An unknown
// port (0) is always omitted.
func dbClientServerPortGetter(explicitlyIncluded bool) attributes.Getter[*Span, attribute.KeyValue] {
	return func(span *Span) attribute.KeyValue {
		if span.HostPort == 0 {
			return attribute.KeyValue{}
		}
		if explicitlyIncluded {
			return ServerPort(span.HostPort)
		}
		if span.HostPort == dbClientDefaultPorts[dbSystemNameForSpan(span)] || HostAsServer(span) == "" {
			return attribute.KeyValue{}
		}
		return ServerPort(span.HostPort)
	}
}

func SpanOTELGettersForDBClient(unresolved UnresolvedNames, explicitPort bool) attributes.NamedGetters[*Span, attribute.KeyValue] {
	base := SpanOTELGetters(unresolved)
	portGetter := dbClientServerPortGetter(explicitPort)
	return func(name attr.Name) (attributes.Getter[*Span, attribute.KeyValue], bool) {
		if name == attr.ServerPort {
			return portGetter, true
		}
		return base(name)
	}
}

func SpanPromGettersForDBClient(unresolved UnresolvedNames, explicitPort bool) attributes.NamedGetters[*Span, string] {
	base := SpanPromGetters(unresolved)
	portGetter := dbClientServerPortGetter(explicitPort)
	return func(name attr.Name) (attributes.Getter[*Span, string], bool) {
		if name == attr.ServerPort {
			return func(span *Span) string {
				// fixed prometheus label sets map omission to an empty label
				if kv := portGetter(span); kv.Valid() {
					return kv.Value.String()
				}
				return ""
			}, true
		}
		return base(name)
	}
}
