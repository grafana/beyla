package metric

import (
	"fmt"
	"maps"
	"slices"

	"github.com/grafana/beyla/pkg/internal/helpers"
)

type AttrSelector struct {
	definition map[Section]Definition
	selector   Selection
}

func NewProvider(groups EnabledGroups, selectorCfg Selection) (*AttrSelector, error) {
	selectorCfg.Normalize()
	// TODO: validate
	return &AttrSelector{
		selector:   selectorCfg,
		definition: getDefinitions(groups),
	}, nil
}

func (p *AttrSelector) For(metricName Name) []string {
	metricAttributes, ok := p.definition[metricName.Section]
	if !ok {
		panic(fmt.Sprintf("BUG! metric not found %+v", metricName))
	}
	inclusionLists, ok := p.selector[metricName.Section]
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
			attr = NormalizeToDot(attr)
			if inclusionLists.includes(attr) {
				addAttributes[attr] = struct{}{}
			}
		}
	}
	maps.DeleteFunc(addAttributes, func(attr string, _ struct{}) bool {
		return inclusionLists.excludes(NormalizeToDot(attr))
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
