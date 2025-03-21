package lint

import (
	"fmt"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

func newTargetRequiredMatcherRule(matcher string) *TargetRuleFunc {
	return &TargetRuleFunc{
		name:        fmt.Sprintf("target-%s-rule", matcher),
		description: fmt.Sprintf("Checks that every PromQL query has a %s matcher.", matcher),
		fn: func(d Dashboard, p Panel, t Target) TargetRuleResults {
			r := TargetRuleResults{}
			// TODO: The RuleSet should be responsible for routing rule checks based on their query type (prometheus, loki, mysql, etc)
			// and for ensuring that the datasource is set.
			if t := getTemplateDatasource(d); t == nil || t.Query != Prometheus {
				// Missing template datasource is a separate rule.
				// Non prometheus datasources don't have rules yet
				return r
			}

			node, err := parsePromQL(t.Expr, d.Templating.List)
			if err != nil {
				// Invalid PromQL is another rule
				return r
			}

			for _, selector := range parser.ExtractSelectors(node) {
				if err := checkForMatcher(selector, matcher, labels.MatchRegexp, fmt.Sprintf("$%s", matcher)); err != nil {
					r.AddError(d, p, t, fmt.Sprintf("invalid PromQL query '%s': %v", t.Expr, err))
				}
			}

			return r
		},
	}
}

func NewTargetJobRule() *TargetRuleFunc {
	return newTargetRequiredMatcherRule("job")
}

func NewTargetInstanceRule() *TargetRuleFunc {
	return newTargetRequiredMatcherRule("instance")
}
