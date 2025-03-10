package rdnscfg

const (
	EBPFProbeGetAddrInfo = "getaddrinfo"
	EBPFProbeResolverXDP = "xdp"
)

type Config struct {
	Resolvers []string
}