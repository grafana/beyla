package rdns

type Config struct {
	// valid values: getaddrinfo, packet
	Resolvers     []string `env:"RDNS_RESOLVERS" envSeparator:","`
}

const (
	ResolverGetAddrInfo = "getaddrinfo"
	ResolverPacket      = "packet"
)
