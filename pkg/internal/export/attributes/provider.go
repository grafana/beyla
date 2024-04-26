package attributes

import (
	"maps"
	"slices"

	"github.com/grafana/beyla/pkg/internal/export/attributes/attr"
	"github.com/grafana/beyla/pkg/internal/helpers"
)

type Provider struct {
	definition map[attr.Section]Definition
	selector   Selection
}

func NewProvider(groups EnabledGroups, selectorCfg Selection) (*Provider, error) {
	selectorCfg.Normalize()
	// TODO: validate
	return &Provider{
		selector:   selectorCfg,
		definition: getDefinitions(groups),
	}, nil
}

func (p *Provider) For(metricName attr.Section) []string {
	metricAttributes, ok := p.definition[metricName]
	if !ok {
		panic("BUG! metric not found " + metricName)
	}
	inclusionLists, ok := p.selector[metricName]
	if !ok {
		attrs := helpers.SetToSlice(metricAttributes.Default())
		slices.Sort(attrs)
		return attrs
	}
	var addAttributes map[string]struct{}
	// if the "include" list is empty, we use the default attributes
	// as included
	if len(inclusionLists.Include) == 0 {
		addAttributes = metricAttributes.Default()
	} else {
		addAttributes = map[string]struct{}{}
		for attr := range metricAttributes.All() {
			attr = normalizeToDot(attr)
			if inclusionLists.includes(attr) {
				addAttributes[attr] = struct{}{}
			}
		}
	}
	maps.DeleteFunc(addAttributes, func(attr string, _ struct{}) bool {
		return inclusionLists.excludes(normalizeToDot(attr))
	})
	attrs := helpers.SetToSlice(addAttributes)
	slices.Sort(attrs)
	return attrs
}

type Default bool

type Definition struct {
	Disabled   bool
	Parents    []*Definition
	Attributes map[string]Default
}

func (p *Definition) All() map[string]struct{} {
	if p.Disabled {
		return map[string]struct{}{}
	}
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
	if p.Disabled {
		return map[string]struct{}{}
	}
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
