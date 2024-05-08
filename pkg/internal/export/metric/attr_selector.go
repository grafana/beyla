package metric

import (
	"fmt"
	"maps"
	"slices"

	"github.com/grafana/beyla/pkg/internal/export/metric/attr"
	"github.com/grafana/beyla/pkg/internal/helpers"
)

// Default is true if an attribute must be reported by default,
// when no "include" selector is specified by the user
type Default bool

// AttrReportGroup defines groups of attributes allowed by a given metrics.
type AttrReportGroup struct {
	// Disabled is true if the attribute group is going to be ignored under
	// some conditions (e.g. the kubernetes metadata when kubernetes is disabled)
	Disabled bool
	// SubGroups are attribute groups related to this instance. If this instance is
	// enabled, they might be also enabled (unless they are explicitly disabled)
	SubGroups []*AttrReportGroup
	// Attributes map of name: enabled for this group
	Attributes map[attr.Name]Default
}

// AttrSelector returns, for each metric, the attributes that have to be reported
// according to the user-provided selection and/or other conditions (e.g. kubernetes is enabled)
type AttrSelector struct {
	definition map[Section]AttrReportGroup
	selector   Selection
}

// NewAttrSelector returns an AttrSelector instance based on the user-provided attributes Selection
// and the auto-detected attribute AttrGroups
func NewAttrSelector(groups AttrGroups, selectorCfg Selection) (*AttrSelector, error) {
	selectorCfg.Normalize()
	// TODO: validate
	return &AttrSelector{
		selector:   selectorCfg,
		definition: getDefinitions(groups),
	}, nil
}

// For returns the list of attribute names for a given metric
func (p *AttrSelector) For(metricName Name) []attr.Name {
	metricAttributes, ok := p.definition[metricName.Section]
	if !ok {
		panic(fmt.Sprintf("BUG! metric not found %+v", metricName))
	}
	inclusionLists, ok := p.selector[metricName.Section]
	if !ok {
		// if the user did not provide any selector, return the default attributes for that metric
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
			if inclusionLists.includes(attrName) {
				addAttributes[attrName] = struct{}{}
			}
		}
	}
	// now remove any attribute specified in the "exclude" list
	maps.DeleteFunc(addAttributes, func(attr attr.Name, _ struct{}) bool {
		return inclusionLists.excludes(attr)
	})
	attrs := helpers.SetToSlice(addAttributes)
	slices.Sort(attrs)
	return attrs
}

// All te attributes for this group and their subgroups, unless they are disabled.
func (p *AttrReportGroup) All() map[attr.Name]struct{} {
	if p.Disabled {
		return map[attr.Name]struct{}{}
	}
	attrs := map[attr.Name]struct{}{}
	for _, parent := range p.SubGroups {
		maps.Copy(attrs, parent.All())
	}
	for k := range p.Attributes {
		attrs[k] = struct{}{}
	}
	return attrs
}

// Default attributes for this group and their subgroups, unless they are disabled.
func (p *AttrReportGroup) Default() map[attr.Name]struct{} {
	if p.Disabled {
		return map[attr.Name]struct{}{}
	}
	attrs := map[attr.Name]struct{}{}
	for _, parent := range p.SubGroups {
		maps.Copy(attrs, parent.Default())
	}
	for k, def := range p.Attributes {
		if def {
			attrs[k] = struct{}{}
		}
	}
	return attrs
}
