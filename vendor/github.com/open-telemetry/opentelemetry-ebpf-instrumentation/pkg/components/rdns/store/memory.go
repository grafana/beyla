package store

import (
	"sync"
)

type DNSEntry struct {
	HostName string
	IPs      []string
}

// TODO: invalidate IPs when its owner (e.g. Pod is removed), or after long time without being
// used/updated
type InMemory struct {
	access sync.RWMutex
	// key: IP address, values: hostname
	// TODO: address scenarios where different hostnames point to a same IP
	entries map[string][]string
}

func NewInMemory() *InMemory {
	return &InMemory{
		entries: map[string][]string{},
	}
}

func (im *InMemory) Store(entry *DNSEntry) {
	im.access.Lock()
	defer im.access.Unlock()
	for _, ip := range entry.IPs {
		// TODO: store IPv4 also with its IPv6 representation
		im.entries[ip] = []string{entry.HostName}
	}
}

func (im *InMemory) GetHostnames(ip string) ([]string, error) {
	im.access.RLock()
	defer im.access.RUnlock()
	return im.entries[ip], nil
}
