// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package instrumentations

type Instrumentation string

const (
	InstrumentationALL   Instrumentation = "*"
	InstrumentationHTTP  Instrumentation = "http"
	InstrumentationGRPC  Instrumentation = "grpc"
	InstrumentationSQL   Instrumentation = "sql"
	InstrumentationRedis Instrumentation = "redis"
	InstrumentationKafka Instrumentation = "kafka"
	InstrumentationGPU   Instrumentation = "gpu"
	InstrumentationMongo Instrumentation = "mongo"
	InstrumentationDNS   Instrumentation = "dns"
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
	flagGPU
	flagMongo
	flagDNS
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
	case InstrumentationGPU:
		return flagGPU
	case InstrumentationMongo:
		return flagMongo
	case InstrumentationDNS:
		return flagDNS
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
	return s.SQLEnabled() || s.RedisEnabled() || s.MongoEnabled()
}

func (s InstrumentationSelection) KafkaEnabled() bool {
	return s&flagKafka != 0
}

func (s InstrumentationSelection) MQEnabled() bool {
	return s.KafkaEnabled()
}

func (s InstrumentationSelection) GPUEnabled() bool {
	return s&flagGPU != 0
}

func (s InstrumentationSelection) MongoEnabled() bool {
	return s&flagMongo != 0
}

func (s InstrumentationSelection) DNSEnabled() bool {
	return s&flagDNS != 0
}
