package attr

import (
	"maps"
)

type Default bool

type Definition struct {
	Parents    []*Definition
	Attributes map[string]Default
}

func (p *Definition) All() map[string]struct{} {
	attrs := map[string]struct{}{}
	for _, parent := range p.Parents {
		maps.Copy(attrs, parent.All())
	}
	for k := range p.Attributes {
		attrs[k] = struct{}{}
	}
	return attrs
}

func (p *Definition) Default() map[string]struct{} {
	attrs := map[string]struct{}{}
	for _, parent := range p.Parents {
		maps.Copy(attrs, parent.Default())
	}
	for k, def := range p.Attributes {
		if def {
			attrs[k] = struct{}{}
		}
	}
	return attrs
}
