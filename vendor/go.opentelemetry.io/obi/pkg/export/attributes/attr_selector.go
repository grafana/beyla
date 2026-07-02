// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package attributes // import "go.opentelemetry.io/obi/pkg/export/attributes"

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	maps2 "go.opentelemetry.io/obi/pkg/internal/helpers/maps"
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

// DefaultSensitiveQueryParams is the built-in list of query-parameter keys whose values
// are redacted by default. Users can extend or narrow it via SensitiveQueryParamsConfig.
var DefaultSensitiveQueryParams = []string{
	// OTel semconv-recommended — https://opentelemetry.io/docs/specs/semconv/http/http-spans/
	"X-Amz-Signature", "X-Amz-Credential", "X-Amz-Security-Token",
	"AWSAccessKeyId", "Signature", "SecurityToken",
	"X-Goog-Signature", "sig",
	// Common sensitive parameters
	"token", "access_token", "refresh_token", "id_token", "jwt",
	"session", "sid", "signature",
	"api_key", "apikey", "client_secret", "secret",
	"password", "pass", "pwd",
	"reset_token", "invite_token", "verify_token",
	"otp", "totp", "mfa_code", "verification_code",
	"SAMLResponse", "assertion",
	"card", "cc", "pan", "cvv",
	"ssn", "tax_id",
}

// SensitiveQueryParamsConfig controls which query-parameter keys are redacted.
// The effective list is DefaultSensitiveQueryParams + Add - Remove.
// When both Add and Remove are empty, DefaultSensitiveQueryParams is used unchanged.
type SensitiveQueryParamsConfig struct {
	Add    []string `yaml:"add" env:"OTEL_EBPF_SENSITIVE_QUERY_PARAMS_ADD" envSeparator:","`
	Remove []string `yaml:"remove" env:"OTEL_EBPF_SENSITIVE_QUERY_PARAMS_REMOVE" envSeparator:","`
}

func (c SensitiveQueryParamsConfig) Effective() []string {
	if len(c.Add) == 0 && len(c.Remove) == 0 {
		return DefaultSensitiveQueryParams
	}
	removeSet := make(map[string]struct{}, len(c.Remove))
	for _, k := range c.Remove {
		removeSet[k] = struct{}{}
	}
	result := make([]string, 0, len(DefaultSensitiveQueryParams)+len(c.Add))
	for _, k := range DefaultSensitiveQueryParams {
		if _, skip := removeSet[k]; !skip {
			result = append(result, k)
		}
	}
	return append(result, c.Add...)
}

// SelectorConfig defines settings for filtering attributes and adding additional attributes
type SelectorConfig struct {
	SelectionCfg            Selection
	ExtraGroupAttributesCfg map[string][]attr.Name
	SensitiveQueryParamsCfg SensitiveQueryParamsConfig
}

// AttrSelector returns, for each metric, the attributes that have to be reported
// according to the user-provided selection and/or other conditions (e.g. kubernetes is enabled)
type AttrSelector struct {
	definition map[Section]AttrReportGroup
	selector   Selection
}

// exactIncludeOnlyAttrs contains optional attributes that must be selected by
// exact name. Wildcard includes such as gen_ai.* do not select these attributes.
var exactIncludeOnlyAttrs = map[attr.Name]struct{}{
	attr.GenAIToolCallArguments: {},
	attr.GenAIToolCallResult:    {},
}

// NewAttrSelector returns an AttrSelector instance based on the user-provided attributes Selection
// and the auto-detected attribute AttrGroups.
// NewAttrSelector assumes that the passed SelectorConfig is already normalized (has already invoked
// its method Normalize on its Selection internal field)
func NewAttrSelector(
	groups AttrGroups,
	cfg *SelectorConfig,
) (*AttrSelector, error) {
	return NewCustomAttrSelector(groups, cfg, getDefinitions)
}

// NewCustomAttrSelector is required for extensions of OBI with other metric types
func NewCustomAttrSelector(
	groups AttrGroups,
	cfg *SelectorConfig,
	extraDefinitionsProvider func(groups AttrGroups, extraGroupAttributes GroupAttributes) map[Section]AttrReportGroup,
) (*AttrSelector, error) {
	extraGroupAttributes := NewGroupAttributes(cfg.ExtraGroupAttributesCfg)

	definitions := getDefinitions(groups, extraGroupAttributes)

	if extraDefinitionsProvider != nil {
		maps.Copy(definitions, extraDefinitionsProvider(groups, extraGroupAttributes))
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
		// if the "include" list is empty in the first iteration, we use the default attributes
		// as included
		if i == 0 && len(il.Include) == 0 {
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
		if requiresExactInclude(attrName) {
			if inclusionLists.includesExact(attrName) {
				matchingAttrs[attrName] = struct{}{}
			}
			continue
		}

		if inclusionLists.includes(attrName) {
			matchingAttrs[attrName] = struct{}{}
		}
	}
}

func requiresExactInclude(name attr.Name) bool {
	_, ok := exactIncludeOnlyAttrs[name]
	return ok
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
