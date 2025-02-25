package store

import (
	"sync"

	"github.com/grafana/beyla/v2/pkg/internal/helpers/maps"
)

type DNSEntry struct {
	HostName string
	IPs      []string
}

type InMemory struct {
	access sync.RWMutex
	// key 1: IP address, key 2: all hostnames for that IP
	// not the most efficient mechanism. Just something quick for initial prototyping
	entries maps.Map2[string, string, struct{}]
}

func NewInMemory() *InMemory {
	return &InMemory{
		entries: maps.Map2[string, string, struct{}]{},
	}
}

func (im *InMemory) PipelineStage(in <-chan DNSEntry) {
	for entry := range in {
		im.access.Lock()
		for _, ip := range entry.IPs {
			// TODO: store IPv4 also with its IPv6 representation
			im.entries.Put(ip, entry.HostName, struct{}{})
		}
		im.access.Unlock()
	}
}

func (im *InMemory) GetHostnames(ip string) []string {
	im.access.RLock()
	defer im.access.RUnlock()
	// TODO: return sorted and cache
	return maps.SetToSlice(im.entries[ip])
}
