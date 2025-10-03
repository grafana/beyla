package cfg

type NetFlowConfig struct {
	CollectorAddress   string `yaml:"collector_address" env:"BEYLA_NETFLOW_COLLECTOR_ADDRESS"`
	CollectorTransport string `yaml:"collector_transport" env:"BEYLA_NETFLOW_COLLECTOR_TRANSPORT"`
}

func (c *NetFlowConfig) Enabled() bool {
	return c.CollectorAddress != ""
}
