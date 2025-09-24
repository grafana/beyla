package spanscfg

type TopologyEnum string

const (
	// TopologyInterCluster can be added to the BEYLA_TOPOLOGY_SPANS list to enable inter-cluster
	// connection spans: simple, individual spans that will let Tempo, at a higher level, provide
	// service map connections between Beyla's placed in different clusters.
	TopologyInterCluster = TopologyEnum("inter_cluster")
)

type Topology struct {
	// nolint:undoc
	Spans []TopologyEnum `yaml:"spans" env:"BEYLA_TOPOLOGY_SPANS"`
}
