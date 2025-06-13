package attributes

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"

	maps2 "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/helpers/maps"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
)

func alog() *slog.Logger {
	return slog.With("component", "attributes")
}

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

func NewAttrReportGroup(
	disabled bool,
	subGroups []*AttrReportGroup,
	attributes map[attr.Name]Default,
	extraAttributes []attr.Name,
) AttrReportGroup {
	for _, extraAttr := range extraAttributes {
		attributes[extraAttr] = true
	}

	return AttrReportGroup{
		Disabled:   disabled,
		SubGroups:  subGroups,
		Attributes: attributes,
	}
}

// GroupAttributes defines additional attributes for each group
type GroupAttributes map[AttrGroups][]attr.Name

func NewGroupAttributes(groupAttrsCfg map[string][]attr.Name) GroupAttributes {
	log := alog()

	groupAttrs := make(GroupAttributes, len(groupAttrsCfg))
	for group, attrs := range groupAttrsCfg {
		attrGroup, err := parseExtraAttrGroup(group)
		if err != nil {
			log.Warn("failed to parse extra attribute group",
				slog.String("group", group),
				slog.String("err", err.Error()),
			)
			continue
		}
		groupAttrs[attrGroup] = attrs
	}

	return groupAttrs
}

func parseExtraAttrGroup(group string) (AttrGroups, error) {
	switch group {
	case "k8s_app_meta":
		return GroupAppKube, nil
	default:
		return UndefinedGroup, fmt.Errorf("group %s is not supported", group)
	}
}

// SelectorConfig defines settings for filtering attributes and adding additional attributes
type SelectorConfig struct {
	SelectionCfg            Selection
	ExtraGroupAttributesCfg map[string][]attr.Name
}

// AttrSelector returns, for each metric, the attributes that have to be reported
// according to the user-provided selection and/or other conditions (e.g. kubernetes is enabled)
type AttrSelector struct {
	definition map[Section]AttrReportGroup
	selector   Selection
}

// NewAttrSelector returns an AttrSelector instance based on the user-provided attributes Selection
// and the auto-detected attribute AttrGroups
func NewAttrSelector(
	groups AttrGroups,
	cfg *SelectorConfig,
) (*AttrSelector, error) {
	return NewCustomAttrSelector(groups, cfg, getDefinitions)
}

func NewCustomAttrSelector(
	groups AttrGroups,
	cfg *SelectorConfig,
	extraDefinitionsProvider func(groups AttrGroups, extraGroupAttributes GroupAttributes) map[Section]AttrReportGroup,
) (*AttrSelector, error) {
	cfg.SelectionCfg.Normalize()
	extraGroupAttributes := NewGroupAttributes(cfg.ExtraGroupAttributesCfg)

	definitions := getDefinitions(groups, extraGroupAttributes)

	if extraDefinitionsProvider != nil {
		for section, group := range extraDefinitionsProvider(groups, extraGroupAttributes) {
			definitions[section] = group
		}
	}

	// TODO: validate
	return &AttrSelector{
		selector:   cfg.SelectionCfg,
		definition: definitions,
	}, nil
}

// For returns the list of enabled attribute names for a given metric
func (p *AttrSelector) For(metricName Name) []attr.Name {
	attributeNames, ok := p.definition[metricName.Section]
	if !ok {
		panic(fmt.Sprintf("BUG! metric not found %+v", metricName))
	}
	allInclusionLists := p.selector.Matching(metricName)
	if len(allInclusionLists) == 0 {
		// if the user did not provide any selector, return the default attributes for that metric
		attrs := maps2.SetToSlice(attributeNames.Default())
		slices.Sort(attrs)
		return attrs
	}
	matchingAttrs := map[attr.Name]struct{}{}
	for i, il := range allInclusionLists {
		p.addIncludedAttributes(matchingAttrs, attributeNames, il)
		// if the "include" lists are empty in the first iteration, we use the default attributes
		// as included
		if i == 0 && len(matchingAttrs) == 0 {
			matchingAttrs = attributeNames.Default()
		}
		// now remove any attribute specified in the "exclude" lists
		p.rmExcludedAttributes(matchingAttrs, il)
	}

	sas := maps2.SetToSlice(matchingAttrs)
	slices.Sort(sas)
	return sas
}

// returns if the inclusion list have contents or not
// this will be useful to decide whether to use the default
// attribute set or not
func (p *AttrSelector) addIncludedAttributes(
	matchingAttrs map[attr.Name]struct{},
	attributeNames AttrReportGroup,
	inclusionLists InclusionLists,
) {
	allAttributes := attributeNames.All()
	for attrName := range allAttributes {
		if inclusionLists.includes(attrName) {
			matchingAttrs[attrName] = struct{}{}
		}
	}
}

func (p *AttrSelector) rmExcludedAttributes(matchingAttrs map[attr.Name]struct{}, inclusionLists InclusionLists) {
	maps.DeleteFunc(matchingAttrs, func(attr attr.Name, _ struct{}) bool {
		return inclusionLists.excludes(attr)
	})
}

// All te attributes for this group and their subgroups, unless they are disabled.
func (p *AttrReportGroup) All() map[attr.Name]struct{} {
	attrs := map[attr.Name]struct{}{}
	if p.Disabled {
		return attrs
	}
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
	attrs := map[attr.Name]struct{}{}
	if p.Disabled {
		return attrs
	}
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
