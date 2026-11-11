// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package agentctl // import "go.opentelemetry.io/obi/pkg/internal/agentctl"

import (
	"sync"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
)

type catalogKey struct {
	pid             app.PID
	start, revision uint64
}
type catalogEntry struct {
	names []string
	bytes int64
}
type Catalog struct {
	mu                               sync.Mutex
	entries                          *simplelru.LRU[catalogKey, catalogEntry]
	bytes, maxBytes, maxProcessBytes int64
}

func NewCatalog(cfg config.DynamicInstrumentationConfig) *Catalog {
	c := &Catalog{maxBytes: cfg.SymbolCacheBytes, maxProcessBytes: cfg.MaxCachedBinaryBytes}
	if cfg.SymbolCacheEntries > 0 && c.maxBytes > 0 && c.maxProcessBytes > 0 {
		c.entries, _ = simplelru.NewLRU[catalogKey, catalogEntry](cfg.SymbolCacheEntries, func(_ catalogKey, entry catalogEntry) { c.bytes -= entry.bytes })
	}
	return c
}

func (c *Catalog) Get(pid app.PID, start, revision uint64) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		return nil, false
	}
	entry, found := c.entries.Get(catalogKey{pid, start, revision})
	return entry.names, found
}

func (c *Catalog) Put(pid app.PID, start, revision uint64, names []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		return
	}
	var cost int64
	for _, name := range names {
		cost += int64(len(name)) + 32
	}
	if cost > c.maxProcessBytes || cost > c.maxBytes {
		return
	}
	for _, key := range c.entries.Keys() {
		if key.pid == pid {
			c.entries.Remove(key)
		}
	}
	for c.bytes+cost > c.maxBytes {
		c.entries.RemoveOldest()
	}
	c.bytes += cost
	c.entries.Add(catalogKey{pid, start, revision}, catalogEntry{names, cost})
}

func (c *Catalog) Remove(pid app.PID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		return
	}
	for _, key := range c.entries.Keys() {
		if key.pid == pid {
			c.entries.Remove(key)
		}
	}
}
