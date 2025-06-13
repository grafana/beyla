package attributes

import (
	"fmt"
	"log/slog"

	attributes2 "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
)

func alog() *slog.Logger {
	return slog.With("component", "attributes")
}

// Default is true if an attribute must be reported by default,
// when no "include" selector is specified by the user
type Default = attributes2.Default

// AttrReportGroup defines groups of attributes allowed by a given metrics.
type AttrReportGroup = attributes2.AttrReportGroup

func newAttrReportGroup(
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
type GroupAttributes = attributes2.GroupAttributes

func newGroupAttributes(groupAttrsCfg map[string][]attr.Name) GroupAttributes {
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

// TODO: remove

// SelectorConfig defines settings for filtering attributes and adding additional attributes
type SelectorConfig = attributes2.SelectorConfig

// AttrSelector returns, for each metric, the attributes that have to be reported
// according to the user-provided selection and/or other conditions (e.g. kubernetes is enabled)
type AttrSelector = attributes2.AttrSelector

// NewAttrSelector returns an AttrSelector instance based on the user-provided attributes Selection
// and the auto-detected attribute AttrGroups
func NewAttrSelector(
	groups AttrGroups,
	cfg *SelectorConfig,
) (*AttrSelector, error) {
	cfg.SelectionCfg.Normalize()

	return attributes2.NewCustomAttrSelector(
		groups,
		cfg,
		getDefinitions,
	)
}
