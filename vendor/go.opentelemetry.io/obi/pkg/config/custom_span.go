// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	CustomSpanMaxArgs        = 12
	CustomSpanStringSize     = 128
	CustomSpanMatchValueSize = 64
	CustomSpanDefaultTTL     = 5 * time.Minute
	CustomSpanStartSuffix    = "_start"
	CustomSpanEndSuffix      = "_end"
)

// CustomSpanConfig declares user-driven spans backed by USDT or uprobes.
// The feature is enabled when Spans is non-empty.
type CustomSpanConfig struct {
	TTL   time.Duration    `yaml:"ttl" env:"OTEL_EBPF_CUSTOM_SPAN_TTL" validate:"gte=0"`
	Spans []CustomSpanSpec `yaml:"spans"`
}

// Enabled reports whether the subsystem should attach probes.
func (c *CustomSpanConfig) Enabled() bool { return len(c.Spans) > 0 }

// CustomSpanSpec defines one span. Exactly one target key inside `on:` is
// required; modifiers (Paired, Match) apply only where noted.
type CustomSpanSpec struct {
	Name  string                    `yaml:"name" validate:"required"`
	On    CustomSpanTarget          `yaml:"on"`
	Attrs map[string]CustomSpanAttr `yaml:"attrs"`
}

// CustomSpanTarget enumerates probe-target options. Exactly one of
// {USDTNoRet, USDTSpan, FunctionNoRet, FunctionSpan} must be non-empty.
type CustomSpanTarget struct {
	// USDTNoRet attaches a uprobe at a single stapsdt probe
	// "<provider>:<name>"; each fire emits a zero-duration marker event.
	USDTNoRet string `yaml:"usdt_noret"`

	// USDTSpan is "<provider>:<base>"; OBI attaches at "<base>_start" and
	// "<base>_end" and emits a span whose duration spans the two probes.
	// Pairing correlates on arg_int[0].
	USDTSpan string `yaml:"usdt_span"`

	// FunctionNoRet attaches an entry uprobe only — zero-duration marker.
	// Use for functions that never return (event loops, noreturn).
	FunctionNoRet string `yaml:"function_noret"`

	// FunctionSpan attaches an entry uprobe + uretprobe; emits a span
	// whose duration is entry-to-return.
	FunctionSpan string `yaml:"function_span"`

	// Match drops events whose probe arg at Match.Arg does not equal
	// Match.Value (byte-for-byte). In-BPF filter; valid on any USDT shape.
	Match *CustomSpanMatch `yaml:"match"`
}

// CustomSpanMatch filters events against a string-valued probe argument.
type CustomSpanMatch struct {
	Arg   uint8  `yaml:"arg"`
	Value string `yaml:"value"`
}

// IsUSDTNoRet reports the marker-style single-shot USDT shape.
func (s *CustomSpanSpec) IsUSDTNoRet() bool { return s.On.USDTNoRet != "" }

// IsUSDTSpan reports the paired _start/_end USDT shape.
func (s *CustomSpanSpec) IsUSDTSpan() bool { return s.On.USDTSpan != "" }

// IsAnyUSDT reports any USDT shape (used for match-filter eligibility).
func (s *CustomSpanSpec) IsAnyUSDT() bool { return s.IsUSDTNoRet() || s.IsUSDTSpan() }

// IsFunctionNoRet reports the entry-only uprobe shape (zero-duration marker).
func (s *CustomSpanSpec) IsFunctionNoRet() bool { return s.On.FunctionNoRet != "" }

// IsFunctionSpan reports the entry-uprobe + uretprobe shape (duration span).
func (s *CustomSpanSpec) IsFunctionSpan() bool { return s.On.FunctionSpan != "" }

// IsAnyFunction reports any function-mode shape.
func (s *CustomSpanSpec) IsAnyFunction() bool { return s.IsFunctionNoRet() || s.IsFunctionSpan() }

// FunctionSymbol returns the configured ELF symbol for function-mode spans.
func (s *CustomSpanSpec) FunctionSymbol() string {
	if s.IsFunctionSpan() {
		return s.On.FunctionSpan
	}
	return s.On.FunctionNoRet
}

// HasMatch reports whether the span has an in-BPF match-value filter.
func (s *CustomSpanSpec) HasMatch() bool { return s.On.Match != nil && s.On.Match.Value != "" }

// USDTStartProbe returns the resolved start probe identifier for usdt_span.
func (s *CustomSpanSpec) USDTStartProbe() string {
	if s.IsUSDTSpan() {
		return s.On.USDTSpan + CustomSpanStartSuffix
	}
	return ""
}

// USDTEndProbe returns the resolved end probe identifier for usdt_span.
func (s *CustomSpanSpec) USDTEndProbe() string {
	if s.IsUSDTSpan() {
		return s.On.USDTSpan + CustomSpanEndSuffix
	}
	return ""
}

// USDTNoRetProbe returns the literal single-shot USDT identifier.
func (s *CustomSpanSpec) USDTNoRetProbe() string { return s.On.USDTNoRet }

type CustomSpanAttrType string

const (
	CustomSpanAttrU8     CustomSpanAttrType = "u8"
	CustomSpanAttrU16    CustomSpanAttrType = "u16"
	CustomSpanAttrU32    CustomSpanAttrType = "u32"
	CustomSpanAttrU64    CustomSpanAttrType = "u64"
	CustomSpanAttrI8     CustomSpanAttrType = "i8"
	CustomSpanAttrI16    CustomSpanAttrType = "i16"
	CustomSpanAttrI32    CustomSpanAttrType = "i32"
	CustomSpanAttrI64    CustomSpanAttrType = "i64"
	CustomSpanAttrString CustomSpanAttrType = "string"
)

// CustomSpanAttr declares one attribute extracted from a probe arg.
// For USDT specs, Type may be omitted on integer attrs — sign and width
// are derived from the .note.stapsdt record. Strings always require
// `type: string`. Function-mode (no ELF note) requires Type on every attr.
type CustomSpanAttr struct {
	Arg  uint8              `yaml:"arg"`
	Type CustomSpanAttrType `yaml:"type"`
}

// IsString reports whether t is a string attr.
func (t CustomSpanAttrType) IsString() bool { return t == CustomSpanAttrString }

// SizeBytes returns the fixed integer size; 0 for string or empty.
func (t CustomSpanAttrType) SizeBytes() uint8 {
	switch t {
	case CustomSpanAttrU8, CustomSpanAttrI8:
		return 1
	case CustomSpanAttrU16, CustomSpanAttrI16:
		return 2
	case CustomSpanAttrU32, CustomSpanAttrI32:
		return 4
	case CustomSpanAttrU64, CustomSpanAttrI64:
		return 8
	}
	return 0
}

// Signed reports whether the integer type is signed.
func (t CustomSpanAttrType) Signed() bool {
	switch t {
	case CustomSpanAttrI8, CustomSpanAttrI16, CustomSpanAttrI32, CustomSpanAttrI64:
		return true
	}
	return false
}

// Empty reports whether the user omitted the type field.
func (t CustomSpanAttrType) Empty() bool { return t == "" }

func (c *CustomSpanConfig) Validate() error {
	if !c.Enabled() {
		return nil
	}
	if c.TTL <= 0 {
		return errors.New("custom_span.ttl must be greater than 0 when spans are configured")
	}
	names := map[string]struct{}{}
	probes := map[string]struct{}{}
	for i := range c.Spans {
		s := &c.Spans[i]
		if err := s.normalizeAndValidate(); err != nil {
			return fmt.Errorf("custom_span.spans[%d]: %w", i, err)
		}
		if _, dup := names[s.Name]; dup {
			return fmt.Errorf("custom_span.spans[%d]: duplicate span name %q", i, s.Name)
		}
		names[s.Name] = struct{}{}
		for _, p := range s.probeIdentifiers() {
			if _, dup := probes[p]; dup {
				return fmt.Errorf("custom_span.spans[%d]: probe %q already used by another span", i, p)
			}
			probes[p] = struct{}{}
		}
	}
	return nil
}

func (s *CustomSpanSpec) normalizeAndValidate() error {
	forms := 0
	for _, set := range []bool{s.IsUSDTNoRet(), s.IsUSDTSpan(), s.IsFunctionNoRet(), s.IsFunctionSpan()} {
		if set {
			forms++
		}
	}
	if forms != 1 {
		return errors.New("on: exactly one of {usdt_noret, usdt_span, function_noret, function_span} must be set")
	}
	if s.Name == "" {
		return errors.New("name is required")
	}
	if s.IsUSDTNoRet() {
		if err := validateProbeIdent(s.On.USDTNoRet); err != nil {
			return err
		}
	}
	if s.IsUSDTSpan() {
		if err := validateProbeIdent(s.On.USDTSpan); err != nil {
			return err
		}
	}
	if s.On.Match != nil {
		if !s.IsAnyUSDT() {
			return errors.New("on.match only valid with usdt_noret or usdt_span")
		}
		if s.On.Match.Arg >= CustomSpanMaxArgs {
			return fmt.Errorf("on.match.arg %d out of range (max %d)", s.On.Match.Arg, CustomSpanMaxArgs-1)
		}
		if s.On.Match.Value == "" {
			return errors.New("on.match.value must be non-empty (or omit `match:` entirely)")
		}
		if len(s.On.Match.Value) >= CustomSpanMatchValueSize {
			return fmt.Errorf("on.match.value length %d exceeds cap %d", len(s.On.Match.Value), CustomSpanMatchValueSize-1)
		}
	}
	for name, a := range s.Attrs {
		if name == "" {
			return errors.New("attribute name cannot be empty")
		}
		if a.Arg >= CustomSpanMaxArgs {
			return fmt.Errorf("attr %q: arg index %d out of range (max %d)", name, a.Arg, CustomSpanMaxArgs-1)
		}
		if a.Type.Empty() {
			if s.IsAnyFunction() {
				return fmt.Errorf("attr %q: type is required for function-mode spans", name)
			}
			// USDT int attr — type derived from ELF at attach time.
			continue
		}
		if !a.Type.IsString() && a.Type.SizeBytes() == 0 {
			return fmt.Errorf("attr %q: invalid type %q", name, a.Type)
		}
	}
	return nil
}

// probeIdentifiers lists the distinct attach targets for this span. Used
// for duplicate detection only. Match-filtered USDT variants are
// disambiguated by appending the match value so a base probe + a
// `match:`-filtered probe can coexist (cookies separate them at runtime
// on kernel ≥5.15).
func (s *CustomSpanSpec) probeIdentifiers() []string {
	suffix := ""
	if s.HasMatch() {
		suffix = "/" + s.On.Match.Value
	}
	switch {
	case s.IsAnyFunction():
		return []string{"function:" + s.FunctionSymbol()}
	case s.IsUSDTSpan():
		return []string{s.On.USDTSpan + CustomSpanStartSuffix + suffix, s.On.USDTSpan + CustomSpanEndSuffix + suffix}
	case s.IsUSDTNoRet():
		return []string{s.On.USDTNoRet + suffix}
	}
	return nil
}

func validateProbeIdent(p string) error {
	parts := strings.SplitN(p, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("probe %q must be of the form provider:name", p)
	}
	return nil
}

func (s *CustomSpanSpec) TargetIdentifier() string {
	if s.IsAnyFunction() {
		return s.FunctionSymbol()
	}
	if s.IsUSDTSpan() {
		return "usdt:" + s.On.USDTSpan
	}
	return "usdt:" + s.On.USDTNoRet
}
