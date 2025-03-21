package yaml

import "net"

type PortAllocator struct {
	ports []int
}

func (p *PortAllocator) Allocate() int {
	if len(p.ports) == 0 {
		panic("no ports available")
	}
	port := p.ports[0]
	p.ports = p.ports[1:]
	return port
}

func (p *PortAllocator) AllocatePorts() *PortConfig {
	return &PortConfig{
		ApplicationPort:    p.Allocate(),
		GrafanaHTTPPort:    p.Allocate(),
		PrometheusHTTPPort: p.Allocate(),
		LokiHTTPPort:       p.Allocate(),
		TempoHTTPPort:      p.Allocate(),
	}
}

func NewPortAllocator(needed int) *PortAllocator {
	ports, err := GetFreePorts(needed * 5)
	if err != nil {
		panic(err)
	}
	return &PortAllocator{ports}
}

func GetFreePorts(count int) ([]int, error) {
	var ports []int
	for i := 0; i < count; i++ {
		addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
		if err != nil {
			return nil, err
		}

		l, err := net.ListenTCP("tcp", addr)
		if err != nil {
			return nil, err
		}
		defer l.Close()
		ports = append(ports, l.Addr().(*net.TCPAddr).Port)
	}
	return ports, nil
}
