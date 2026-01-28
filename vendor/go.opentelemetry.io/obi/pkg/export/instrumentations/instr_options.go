// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumentations // import "go.opentelemetry.io/obi/pkg/export/instrumentations"

type Instrumentation string

const (
	InstrumentationALL       Instrumentation = "*"
	InstrumentationHTTP      Instrumentation = "http"
	InstrumentationGRPC      Instrumentation = "grpc"
	InstrumentationSQL       Instrumentation = "sql"
	InstrumentationRedis     Instrumentation = "redis"
	InstrumentationKafka     Instrumentation = "kafka"
	InstrumentationMQTT      Instrumentation = "mqtt"
	InstrumentationGPU       Instrumentation = "gpu"
	InstrumentationMongo     Instrumentation = "mongo"
	InstrumentationDNS       Instrumentation = "dns"
	InstrumentationCouchbase Instrumentation = "couchbase"
	// Traces export selectively enables only some instrumentations by
	// default. If you add a new instrumentation type, make sure you
	// update the TracesConfig accordingly. Metrics do ALL == "*".
)

type InstrumentationSelection uint64

const (
	flagAll  = 0xFFFFFFFF_FFFFFFFF
	flagHTTP = InstrumentationSelection(1 << iota)
	flagGRPC
	flagSQL
	flagRedis
	flagKafka
	flagMQTT
	flagGPU
	flagMongo
	flagDNS
	flagCouchbase
)

func instrumentationToFlag(str Instrumentation) InstrumentationSelection {
	switch str {
	case InstrumentationALL:
		return flagAll
	case InstrumentationHTTP:
		return flagHTTP
	case InstrumentationGRPC:
		return flagGRPC
	case InstrumentationSQL:
		return flagSQL
	case InstrumentationRedis:
		return flagRedis
	case InstrumentationKafka:
		return flagKafka
	case InstrumentationMQTT:
		return flagMQTT
	case InstrumentationGPU:
		return flagGPU
	case InstrumentationMongo:
		return flagMongo
	case InstrumentationDNS:
		return flagDNS
	case InstrumentationCouchbase:
		return flagCouchbase
	}
	return 0
}

func NewInstrumentationSelection(instrumentations []Instrumentation) InstrumentationSelection {
	selection := InstrumentationSelection(0)
	for _, i := range instrumentations {
		selection |= instrumentationToFlag(i)
	}

	return selection
}

func (s InstrumentationSelection) HTTPEnabled() bool {
	return s&flagHTTP != 0
}

func (s InstrumentationSelection) GRPCEnabled() bool {
	return s&flagGRPC != 0
}

func (s InstrumentationSelection) SQLEnabled() bool {
	return s&flagSQL != 0
}

func (s InstrumentationSelection) RedisEnabled() bool {
	return s&flagRedis != 0
}

func (s InstrumentationSelection) DBEnabled() bool {
	return s.SQLEnabled() || s.RedisEnabled() || s.MongoEnabled() || s.CouchbaseEnabled()
}

func (s InstrumentationSelection) KafkaEnabled() bool {
	return s&flagKafka != 0
}

func (s InstrumentationSelection) MQTTEnabled() bool {
	return s&flagMQTT != 0
}

func (s InstrumentationSelection) MQEnabled() bool {
	return s.KafkaEnabled() || s.MQTTEnabled()
}

func (s InstrumentationSelection) GPUEnabled() bool {
	return s&flagGPU != 0
}

func (s InstrumentationSelection) MongoEnabled() bool {
	return s&flagMongo != 0
}

func (s InstrumentationSelection) CouchbaseEnabled() bool {
	return s&flagCouchbase != 0
}

func (s InstrumentationSelection) DNSEnabled() bool {
	return s&flagDNS != 0
}
