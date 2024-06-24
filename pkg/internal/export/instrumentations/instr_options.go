package instrumentations

type Instrumentation string

type InstrumentationSelection map[Instrumentation]bool

const (
	InstrumentationALL   = "*"
	InstrumentationHTTP  = "http"
	InstrumentationGRPC  = "grpc"
	InstrumentationSQL   = "sql"
	InstrumentationRedis = "redis"
	InstrumentationKafka = "kafka"
)

func NewInstrumentationSelection(instrumentations []string) InstrumentationSelection {
	selection := InstrumentationSelection{}
	for _, i := range instrumentations {
		selection[Instrumentation(i)] = true
	}

	return selection
}

func (s InstrumentationSelection) instrumentationEnabled(i Instrumentation) bool {
	_, ok := s[i]
	if !ok {
		_, ok = s[InstrumentationALL]
	}
	return ok
}

func (s InstrumentationSelection) HTTPEnabled() bool {
	return s.instrumentationEnabled(InstrumentationHTTP)
}

func (s InstrumentationSelection) GRPCEnabled() bool {
	return s.instrumentationEnabled(InstrumentationGRPC)
}

func (s InstrumentationSelection) SQLEnabled() bool {
	return s.instrumentationEnabled(InstrumentationSQL)
}

func (s InstrumentationSelection) RedisEnabled() bool {
	return s.instrumentationEnabled(InstrumentationRedis)
}

func (s InstrumentationSelection) DBEnabled() bool {
	return s.SQLEnabled() || s.RedisEnabled()
}

func (s InstrumentationSelection) KafkaEnabled() bool {
	return s.instrumentationEnabled(InstrumentationKafka)
}

func (s InstrumentationSelection) MQEnabled() bool {
	return s.KafkaEnabled()
}
