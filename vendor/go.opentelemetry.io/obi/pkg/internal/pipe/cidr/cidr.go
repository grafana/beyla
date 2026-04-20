// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package cidr // import "go.opentelemetry.io/obi/pkg/internal/pipe/cidr"

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/yl2chen/cidranger"
	"gopkg.in/yaml.v3"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

func glog() *slog.Logger {
	return slog.With("component", "cidr.Decorator")
}

// Definition represents a single CIDR entry with an optional human-readable name.
// When Name is empty, the CIDR string itself is used as the attribute value.
type Definition struct {
	CIDR string `yaml:"cidr" json:"cidr"`
	Name string `yaml:"name" json:"name"`
}

// Label returns the name if set, otherwise the CIDR string.
func (d Definition) Label() string {
	if d.Name != "" {
		return d.Name
	}
	return d.CIDR
}

// Definitions contains a list of CIDRs to be set as the "src.cidr" and "dst.cidr"
// attribute as a function of the source and destination IP addresses.
// It supports two YAML formats:
//   - A list of CIDR strings: ["10.0.0.0/8", "192.168.0.0/16"]
//   - A list of named CIDRs: [{cidr: "10.0.0.0/8", name: "internal"}, ...]
type Definitions []Definition

func (c Definitions) Enabled() bool {
	return len(c) > 0
}

// UnmarshalYAML supports both a list of plain CIDR strings and a list of
// objects with "cidr" and "name" keys.
func (c *Definitions) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.SequenceNode {
		return fmt.Errorf("cidrs: expected a YAML sequence, got kind %v", value.Kind)
	}
	defs := make(Definitions, 0, len(value.Content))
	for i, item := range value.Content {
		switch item.Kind {
		case yaml.ScalarNode:
			defs = append(defs, Definition{CIDR: item.Value})
		case yaml.MappingNode:
			var d Definition
			if err := item.Decode(&d); err != nil {
				return fmt.Errorf("cidrs[%d]: %w", i, err)
			}
			if d.CIDR == "" {
				return fmt.Errorf("cidrs[%d]: missing required 'cidr' field", i)
			}
			defs = append(defs, d)
		default:
			return fmt.Errorf("cidrs[%d]: unexpected YAML node kind %v", i, item.Kind)
		}
	}
	*c = defs
	return nil
}

// UnmarshalText parses comma-separated CIDR strings from environment variables.
func (c *Definitions) UnmarshalText(text []byte) error {
	s := strings.TrimSpace(string(text))
	if s == "" {
		*c = nil
		return nil
	}
	parts := strings.Split(s, ",")
	defs := make(Definitions, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			defs = append(defs, Definition{CIDR: p})
		}
	}
	*c = defs
	return nil
}

// Validate checks that all CIDR strings are valid.
func (c Definitions) Validate() error {
	for i, d := range c {
		if _, _, err := net.ParseCIDR(d.CIDR); err != nil {
			return fmt.Errorf("cidrs[%d]: parsing CIDR %q: %w", i, d.CIDR, err)
		}
	}
	return nil
}

// JSONSchema returns a schema that accepts both a list of CIDR strings and a
// list of objects with "cidr" and "name" keys.
func (Definitions) JSONSchema() *jsonschema.Schema {
	namedCIDRProps := jsonschema.NewProperties()
	namedCIDRProps.Set("cidr", &jsonschema.Schema{
		Type:        "string",
		Description: "A CIDR range (e.g. \"10.0.0.0/8\").",
	})
	namedCIDRProps.Set("name", &jsonschema.Schema{
		Type:        "string",
		Description: "A human-readable name for this CIDR. Used as the attribute value instead of the CIDR string.",
	})
	return &jsonschema.Schema{
		Type: "array",
		Items: &jsonschema.Schema{
			OneOf: []*jsonschema.Schema{
				{
					Type:        "string",
					Description: "A CIDR range (e.g. \"10.0.0.0/8\"). The CIDR string is used as the attribute value.",
				},
				{
					Type:        "object",
					Properties:  namedCIDRProps,
					Required:    []string{"cidr"},
					Description: "A named CIDR entry.",
				},
			},
		},
		Description: "A list of CIDRs to be set as the \"src.cidr\" and \"dst.cidr\" " +
			"attribute as a function of the source and destination IP addresses. " +
			"Each entry can be a plain CIDR string or an object with \"cidr\" and \"name\" fields.",
	}
}

type ipGrouper struct {
	ranger cidranger.Ranger
}

func DecoratorProvider[T any](g Definitions, attrs func(T) *pipe.CommonAttrs,
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !g.Enabled() {
			return swarm.Bypass(input, output)
		}
		grouper, err := newIPGrouper(g)
		if err != nil {
			return nil, fmt.Errorf("instantiating IP grouper: %w", err)
		}
		in := input.Subscribe(msg.SubscriberName("cidr.Decorator"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, glog().Debug, func(items []T) {
				for _, item := range items {
					grouper.decorate(attrs(item))
				}
				output.Send(items)
			})
		}, nil
	}
}

type customRangerEntry struct {
	ipNet net.IPNet
	label string
}

func (b *customRangerEntry) Network() net.IPNet {
	return b.ipNet
}

func newIPGrouper(cfg Definitions) (ipGrouper, error) {
	g := ipGrouper{ranger: cidranger.NewPCTrieRanger()}
	for _, def := range cfg {
		_, ipNet, err := net.ParseCIDR(def.CIDR)
		if err != nil {
			return g, fmt.Errorf("parsing CIDR %s: %w", def.CIDR, err)
		}
		if err := g.ranger.Insert(&customRangerEntry{ipNet: *ipNet, label: def.Label()}); err != nil {
			return g, fmt.Errorf("inserting CIDR %s: %w", def.CIDR, err)
		}
	}
	return g, nil
}

func (g *ipGrouper) CIDR(ip net.IP) string {
	entries, _ := g.ranger.ContainingNetworks(ip)
	if len(entries) == 0 {
		return ""
	}
	// will always return the narrower matching CIDR
	return entries[len(entries)-1].(*customRangerEntry).label
}

func (g *ipGrouper) decorate(a *pipe.CommonAttrs) {
	if a.Metadata == nil {
		a.Metadata = map[attr.Name]string{}
	}
	if srcCIDR := g.CIDR(a.SrcAddr[:]); srcCIDR != "" {
		a.Metadata[attr.SrcCIDR] = srcCIDR
	}
	if dstCIDR := g.CIDR(a.DstAddr[:]); dstCIDR != "" {
		a.Metadata[attr.DstCIDR] = dstCIDR
	}
}
