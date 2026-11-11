// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/gobwas/glob"
	"github.com/hashicorp/golang-lru/v2/simplelru"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
)

type (
	functionLocation struct{ address, size uint64 }
	symbolIdentity   struct {
		dev, inode     uint64
		size, modified int64
	}
)

type cachedSymbols struct {
	functions map[string]functionLocation
	bytes     int64
}

// SymbolCache resolves executable functions without requiring an attached tracer.
type SymbolCache struct {
	mu                              sync.Mutex
	entries                         *simplelru.LRU[symbolIdentity, cachedSymbols]
	bytes, maxBytes, maxBinaryBytes int64
}

func NewSymbolCache(cfg config.DynamicInstrumentationConfig) *SymbolCache {
	c := &SymbolCache{maxBytes: cfg.SymbolCacheBytes, maxBinaryBytes: cfg.MaxCachedBinaryBytes}
	if cfg.SymbolCacheEntries > 0 && c.maxBytes > 0 && c.maxBinaryBytes > 0 {
		c.entries, _ = simplelru.NewLRU[symbolIdentity, cachedSymbols](cfg.SymbolCacheEntries, func(_ symbolIdentity, v cachedSymbols) { c.bytes -= v.bytes })
	}
	return c
}

func (c *SymbolCache) symbols(path string, ef *elf.File) (map[string]functionLocation, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("executable identity unavailable")
	}
	key := symbolIdentity{dev: stat.Dev, inode: stat.Ino, size: info.Size(), modified: info.ModTime().UnixNano()}
	if c.entries != nil {
		if cached, found := c.entries.Get(key); found {
			return cached.functions, nil
		}
	}
	functions, err := readFunctionSymbols(ef)
	if err != nil {
		return nil, err
	}
	var cost int64
	for name := range functions {
		cost += int64(len(name)) + 128
	}
	if c.entries != nil && cost <= c.maxBinaryBytes && cost <= c.maxBytes {
		for c.bytes+cost > c.maxBytes {
			c.entries.RemoveOldest()
		}
		c.bytes += cost
		c.entries.Add(key, cachedSymbols{functions: functions, bytes: cost})
	}
	return functions, nil
}

func readFunctionSymbols(ef *elf.File) (map[string]functionLocation, error) {
	functions := map[string]functionLocation{}
	syms, _ := ef.Symbols()
	dynamic, _ := ef.DynamicSymbols()
	for _, symbols := range [][]elf.Symbol{syms, dynamic} {
		for _, symbol := range symbols {
			if elf.ST_TYPE(symbol.Info) == elf.STT_FUNC && symbol.Value != 0 && symbol.Section != elf.SHN_UNDEF {
				functions[strings.Clone(symbol.Name)] = functionLocation{symbol.Value, symbol.Size}
			}
		}
	}
	if DetectFunctionLang(ef) == FunctionLangGo {
		table, err := goexec.GoSymbolTable(ef)
		if err != nil && len(functions) == 0 {
			return nil, err
		}
		if table != nil {
			for _, function := range table.Funcs {
				if function.End > function.Entry {
					functions[strings.Clone(function.Name)] = functionLocation{function.Entry, function.End - function.Entry}
				}
			}
		}
	}
	if len(functions) == 0 {
		return nil, errors.New("executable has no resolvable function symbols")
	}
	return functions, nil
}

func (pt *ProcessTracer) ResolveLiveSymbols(pid app.PID, pattern string) ([]string, error) {
	return pt.symbols.ResolveLiveSymbols(pid, pattern)
}

func (c *SymbolCache) ResolveLiveSymbols(pid app.PID, pattern string) ([]string, error) {
	matcher, err := glob.Compile(pattern)
	if err != nil {
		return nil, err
	}
	path, _, err := resolveExePath(pid)
	if err != nil {
		return nil, err
	}
	ef, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer ef.Close()
	symbols, err := c.symbols(path, ef)
	if err != nil {
		return nil, err
	}
	// Exact symbol names take precedence over glob metacharacters in Go receivers.
	if _, ok := symbols[pattern]; ok {
		return []string{pattern}, nil
	}
	var names []string
	for name := range symbols {
		if matcher.Match(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("function pattern %q matched no symbols", pattern)
	}
	return names, nil
}
