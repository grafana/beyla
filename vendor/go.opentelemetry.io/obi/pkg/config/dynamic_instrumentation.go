// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gobwas/glob"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

type DynamicInstrumentationConfig struct {
	Enabled              bool                         `yaml:"enabled" env:"OTEL_EBPF_DYNAMIC_INSTRUMENTATION_ENABLED"`
	ListenAddress        string                       `yaml:"listen_address" env:"OTEL_EBPF_DYNAMIC_INSTRUMENTATION_LISTEN_ADDRESS"`
	TTL                  time.Duration                `yaml:"ttl"`
	WatchInterval        time.Duration                `yaml:"watch_interval"`
	RequestTimeout       time.Duration                `yaml:"request_timeout"`
	SymbolCacheEntries   int                          `yaml:"symbol_cache_entries"`
	SymbolCacheBytes     int64                        `yaml:"symbol_cache_bytes"`
	MaxCachedBinaryBytes int64                        `yaml:"max_cached_binary_bytes"`
	MaxProbes            int                          `yaml:"max_probes"`
	Rules                []DynamicInstrumentationRule `yaml:"rules"`
}

type DynamicInstrumentationRule struct {
	Service services.GlobDefinitionCriteria `yaml:"service"`
	Spans   []CustomSpanSpec                `yaml:"spans"`
	Patches []PatchSpec                     `yaml:"patches"`
}

const (
	PatchActionReturn = "return"
	MaxPatchTTL       = 24 * time.Hour
)

// PatchSpec makes one Java method return a constant String until its TTL ends. The descriptor
// is required so overloads are never patched by accident.
type PatchSpec struct {
	Class      string        `yaml:"class"`
	Method     string        `yaml:"method"`
	Descriptor string        `yaml:"descriptor"`
	Action     string        `yaml:"action"`
	Value      string        `yaml:"value"`
	TTL        time.Duration `yaml:"ttl"`
}

func (p *PatchSpec) Target() string {
	return p.Class + "." + p.Method + p.Descriptor
}

func (p *PatchSpec) Validate() error {
	if p.Class == "" || p.Method == "" || p.Descriptor == "" {
		return errors.New("patch class, method and descriptor are required")
	}
	if !strings.HasPrefix(p.Descriptor, "(") || !strings.HasSuffix(p.Descriptor, ")Ljava/lang/String;") {
		return fmt.Errorf("patch %s: descriptor must be a JVM method descriptor returning java.lang.String", p.Target())
	}
	if p.Action != PatchActionReturn {
		return fmt.Errorf("patch %s: action must be %q", p.Target(), PatchActionReturn)
	}
	if p.TTL <= 0 || p.TTL > MaxPatchTTL {
		return fmt.Errorf("patch %s: ttl must be between 0 and %s", p.Target(), MaxPatchTTL)
	}
	return nil
}

func (c *DynamicInstrumentationConfig) IsEnabled() bool {
	return c.Enabled || c.ListenAddress != "" || len(c.Rules) != 0
}

func (c *DynamicInstrumentationConfig) Validate() error {
	if !c.IsEnabled() {
		return nil
	}
	if c.TTL <= 0 || c.WatchInterval <= 0 || c.RequestTimeout <= 0 {
		return errors.New("dynamic_instrumentation: ttl, watch_interval and request_timeout must be positive")
	}
	if c.SymbolCacheEntries < 0 || c.SymbolCacheBytes < 0 || c.MaxCachedBinaryBytes < 0 || c.MaxProbes <= 0 || c.MaxProbes > 1<<20 {
		return errors.New("dynamic_instrumentation: cache limits must be nonnegative and max_probes must be between 1 and 1048576")
	}
	if c.ListenAddress != "" {
		_, _, err := net.SplitHostPort(c.ListenAddress)
		if err != nil {
			return fmt.Errorf("dynamic_instrumentation.listen_address: %w", err)
		}
	}
	for i := range c.Rules {
		if err := c.Rules[i].Validate(); err != nil {
			return fmt.Errorf("dynamic_instrumentation.rules[%d]: %w", i, err)
		}
	}
	return nil
}

func (r *DynamicInstrumentationRule) Validate() error {
	if len(r.Service) == 0 {
		return errors.New("service must contain at least one selector")
	}
	if err := r.Service.Validate(); err != nil {
		return err
	}
	if len(r.Spans) == 0 && len(r.Patches) == 0 {
		return errors.New("spans or patches must not be empty")
	}
	for i := range r.Patches {
		if err := r.Patches[i].Validate(); err != nil {
			return err
		}
	}
	c := CustomSpanConfig{TTL: CustomSpanDefaultTTL, Spans: r.Spans}
	if err := c.Validate(); err != nil {
		return err
	}
	for _, span := range r.Spans {
		if span.IsAnyFunction() {
			if _, err := glob.Compile(span.FunctionSymbol()); err != nil {
				return fmt.Errorf("function glob: %w", err)
			}
		}
	}
	return nil
}

func DefaultDynamicInstrumentationConfig() DynamicInstrumentationConfig {
	return DynamicInstrumentationConfig{TTL: CustomSpanDefaultTTL, WatchInterval: time.Second, RequestTimeout: 10 * time.Second, SymbolCacheEntries: 32, SymbolCacheBytes: 64 << 20, MaxCachedBinaryBytes: 8 << 20, MaxProbes: 1024}
}
