// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import "go.opentelemetry.io/obi/pkg/export/instrumentations"

type protocolName string

const (
	protocolHTTP      protocolName = "http"
	protocolGRPC      protocolName = "grpc"
	protocolSQL       protocolName = "sql"
	protocolRedis     protocolName = "redis"
	protocolKafka     protocolName = "kafka"
	protocolMongo     protocolName = "mongo"
	protocolCouchbase protocolName = "couchbase"
	protocolDNS       protocolName = "dns"
	protocolGPU       protocolName = "gpu"
	protocolAerospike protocolName = "aerospike"
)

type protocolMapping struct {
	name           protocolName
	instr          instrumentations.Instrumentation
	appMetrics     bool
	metricWildcard bool
}

var runtimeInstrumentations = []instrumentations.Instrumentation{
	instrumentations.InstrumentationHTTP,
	instrumentations.InstrumentationGRPC,
	instrumentations.InstrumentationSQL,
	instrumentations.InstrumentationRedis,
	instrumentations.InstrumentationKafka,
	instrumentations.InstrumentationMQTT,
	instrumentations.InstrumentationNATS,
	instrumentations.InstrumentationAMQP,
	instrumentations.InstrumentationGPU,
	instrumentations.InstrumentationMongo,
	instrumentations.InstrumentationDNS,
	instrumentations.InstrumentationCouchbase,
	instrumentations.InstrumentationGenAI,
	instrumentations.InstrumentationMemcached,
	instrumentations.InstrumentationSunRPC,
	instrumentations.InstrumentationAerospike,
}

var protocolMappings = []protocolMapping{
	{name: protocolHTTP, instr: instrumentations.InstrumentationHTTP, appMetrics: true, metricWildcard: true},
	{name: protocolGRPC, instr: instrumentations.InstrumentationGRPC, appMetrics: true, metricWildcard: true},
	{name: protocolSQL, instr: instrumentations.InstrumentationSQL, appMetrics: true, metricWildcard: true},
	{name: protocolRedis, instr: instrumentations.InstrumentationRedis, appMetrics: true, metricWildcard: true},
	{name: protocolKafka, instr: instrumentations.InstrumentationKafka, appMetrics: true, metricWildcard: true},
	{name: protocolMongo, instr: instrumentations.InstrumentationMongo, appMetrics: true, metricWildcard: true},
	{name: protocolCouchbase, instr: instrumentations.InstrumentationCouchbase, appMetrics: true, metricWildcard: true},
	{name: protocolDNS, instr: instrumentations.InstrumentationDNS, appMetrics: false},
	{name: protocolGPU, instr: instrumentations.InstrumentationGPU, appMetrics: true, metricWildcard: true},
	{name: protocolAerospike, instr: instrumentations.InstrumentationAerospike, appMetrics: true, metricWildcard: true},
}
