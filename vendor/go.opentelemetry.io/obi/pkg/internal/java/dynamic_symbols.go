// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"sync"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
)

type javaSymbolIdentity struct {
	pid             app.PID
	start, revision uint64
}

type javaSymbols struct {
	names []string
	bytes int64
}

type javaSymbolCache struct {
	mu                               sync.Mutex
	entries                          *simplelru.LRU[javaSymbolIdentity, javaSymbols]
	bytes, maxBytes, maxProcessBytes int64
}

func newJavaSymbolCache(cfg config.DynamicInstrumentationConfig) *javaSymbolCache {
	c := &javaSymbolCache{maxBytes: cfg.SymbolCacheBytes, maxProcessBytes: cfg.MaxCachedBinaryBytes}
	if cfg.SymbolCacheEntries > 0 && c.maxBytes > 0 && c.maxProcessBytes > 0 {
		c.entries, _ = simplelru.NewLRU[javaSymbolIdentity, javaSymbols](cfg.SymbolCacheEntries, func(_ javaSymbolIdentity, entry javaSymbols) { c.bytes -= entry.bytes })
	}
	return c
}

func (c *javaSymbolCache) get(key javaSymbolIdentity) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		return nil, false
	}
	entry, found := c.entries.Get(key)
	return entry.names, found
}

func (c *javaSymbolCache) put(key javaSymbolIdentity, names []string) {
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
	for _, prior := range c.entries.Keys() {
		if prior.pid == key.pid {
			c.entries.Remove(prior)
		}
	}
	for c.bytes+cost > c.maxBytes {
		c.entries.RemoveOldest()
	}
	c.bytes += cost
	c.entries.Add(key, javaSymbols{names: names, bytes: cost})
}

func (c *javaSymbolCache) remove(pid app.PID) {
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
