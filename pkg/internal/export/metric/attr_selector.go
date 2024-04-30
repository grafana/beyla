package metric

import (
	"fmt"
	"maps"
	"slices"

	"github.com/grafana/beyla/pkg/internal/export/metric/attr"
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

func (p *AttrSelector) For(metricName Name) []attr.Name {
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
	var addAttributes map[attr.Name]struct{}
	// if the "include" list is empty, we use the default attributes
	// as included
	if len(inclusionLists.Include) == 0 {
		addAttributes = metricAttributes.Default()
	} else {
		addAttributes = map[attr.Name]struct{}{}
		for attrName := range metricAttributes.All() {
			attrName = attr.Name(NormalizeToDot(string(attrName)))
			if inclusionLists.includes(string(attrName)) {
				addAttributes[attrName] = struct{}{}
			}
		}
	}
	maps.DeleteFunc(addAttributes, func(attr attr.Name, _ struct{}) bool {
		return inclusionLists.excludes(NormalizeToDot(string(attr)))
	})
	attrs := helpers.SetToSlice(addAttributes)
	slices.Sort(attrs)
	return attrs
}

type Default bool

type Definition struct {
	Disabled   bool
	Parents    []*Definition
	Attributes map[attr.Name]Default
}

func (p *Definition) All() map[attr.Name]struct{} {
	if p.Disabled {
		return map[attr.Name]struct{}{}
	}
	attrs := map[attr.Name]struct{}{}
	for _, parent := range p.Parents {
		maps.Copy(attrs, parent.All())
	}
	for k := range p.Attributes {
		attrs[k] = struct{}{}
	}
	return attrs
}

func (p *Definition) Default() map[attr.Name]struct{} {
	if p.Disabled {
		return map[attr.Name]struct{}{}
	}
	attrs := map[attr.Name]struct{}{}
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
