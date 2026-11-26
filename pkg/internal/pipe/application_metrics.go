package pipe

import (
	"maps"
	"slices"
	"strings"

	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/obi"
)

// applicationMetricConfig makes the HTTP server endpoint dimensions opt-in until
// OBI supplies those defaults. Both application metric exporters use this copy.
func applicationMetricConfig(config *obi.Config, groups attributes.AttrGroups) (*obi.Config, error) {
	attrs := &config.Attributes
	selector, err := attributes.NewAttrSelector(groups, &attributes.SelectorConfig{
		SelectionCfg:            attrs.Select,
		ExtraGroupAttributesCfg: attrs.ExtraGroupAttributes,
		UseV2Selection:          attrs.UseV2Selection,
	})
	if err != nil {
		return nil, err
	}

	matching := attrs.Select.Matching
	if attrs.UseV2Selection {
		matching = attrs.Select.MatchingV2
	}
	// Extra group attributes contribute defaults independently of the
	// instrument's own definition, including when Kubernetes is enabled.
	extra := attrs.ExtraGroupAttributes["app"]
	if groups.Has(attributes.GroupKubernetes) {
		extra = slices.Concat(extra, attrs.ExtraGroupAttributes["k8s_app_meta"])
	}

	effective := *config
	effective.Attributes.Select = make(attributes.Selection, len(attrs.Select)+3)
	maps.Copy(effective.Attributes.Select, attrs.Select)
	for _, metric := range []attributes.Name{attributes.HTTPServerDuration, attributes.HTTPServerRequestSize, attributes.HTTPServerResponseSize} {
		// A nonempty first include replaces the defaults. Even adding an
		// empty-include rule could change which rule OBI evaluates first.
		if rules := matching(metric); len(rules) > 0 && len(rules[0].Include) > 0 {
			continue
		}
		var exclude []string
		selected := selector.For(metric)
		for _, key := range []attr.Name{attr.ServerAddr, attr.ServerPort} {
			if slices.Contains(selected, key) && !selector.ExplicitlyIncluded(metric, key) && !slices.Contains(extra, key) {
				exclude = append(exclude, string(key))
			}
		}
		if len(exclude) > 0 {
			// Match this instrument exactly. A literal "http.server" prefix
			// would also filter custom metadata on OBI's traces.target.info.
			section := attributes.Section(strings.Replace(string(metric.Section), ".", "[.]", 1))
			rule := attrs.Select[section]
			rule.Exclude = slices.Concat(rule.Exclude, exclude)
			effective.Attributes.Select[section] = rule
		}
	}
	return &effective, nil
}
