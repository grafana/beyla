package instrumentations

type InstrumentationSelection uint64

const (
	InstrumentationALL   = "*"
	InstrumentationHTTP  = "http"
	InstrumentationGRPC  = "grpc"
	InstrumentationSQL   = "sql"
	InstrumentationRedis = "redis"
	InstrumentationKafka = "kafka"
	InstrumentationGPU   = "gpu"
	InstrumentationMongo = "mongo"
)

const (
	flagAll  = 0xFFFFFFFF_FFFFFFFF
	flagHTTP = InstrumentationSelection(1 << iota)
	flagGRPC
	flagSQL
	flagRedis
	flagKafka
	flagGPU
	flagMongo
)

func strToFlag(str string) InstrumentationSelection {
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
	}
	return 0
}

func NewInstrumentationSelection(instrumentations []string) InstrumentationSelection {
	selection := InstrumentationSelection(0)
	for _, i := range instrumentations {
		selection |= strToFlag(i)
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
