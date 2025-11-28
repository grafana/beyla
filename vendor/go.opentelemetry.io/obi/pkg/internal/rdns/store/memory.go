// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"sync"

	"github.com/hashicorp/golang-lru/v2/simplelru"
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
	entries *simplelru.LRU[string, []string]
}

func NewInMemory(cacheSize int) (*InMemory, error) {
	cache, err := simplelru.NewLRU[string, []string](cacheSize, nil)
	if err != nil {
		return nil, err
	}
	return &InMemory{
		entries: cache,
	}, nil
}

func (im *InMemory) Store(entry *DNSEntry) {
	im.access.Lock()
	defer im.access.Unlock()
	for _, ip := range entry.IPs {
		// TODO: store IPv4 also with its IPv6 representation
		im.entries.Add(ip, []string{entry.HostName})
	}
}

func (im *InMemory) StorePair(ip, name string) {
	im.access.Lock()
	defer im.access.Unlock()
	im.entries.Add(ip, []string{name})
}

func (im *InMemory) GetHostnames(ip string) ([]string, error) {
	im.access.RLock()
	defer im.access.RUnlock()
	r, _ := im.entries.Get(ip)
	return r, nil
}
