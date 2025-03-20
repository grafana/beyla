package lint

import (
	"fmt"

	"github.com/prometheus/prometheus/promql/parser"
)

// panelHasQueries returns true is the panel has queries we should try and
// validate.  We allow-list panels here to prevent false positives with
// new panel types we don't understand.
func panelHasQueries(p Panel) bool {
	types := []string{panelTypeSingleStat, panelTypeGauge, panelTypeTimeTable, "stat", "state-timeline", panelTypeTimeSeries}
	for _, t := range types {
		if p.Type == t {
			return true
		}
	}
	return false
}

// parsePromQL returns the parsed PromQL statement from a panel,
// replacing eg [$__rate_interval] with [5m] so queries parse correctly.
// We also replace various other Grafana global variables.
func parsePromQL(expr string, variables []Template) (parser.Expr, error) {
	expr, err := expandVariables(expr, variables)
	if err != nil {
		return nil, fmt.Errorf("could not expand variables: %w", err)
	}
	return parser.ParseExpr(expr)
}

// NewTargetPromQLRule builds a lint rule for panels with Prometheus queries which checks:
// - the query is valid PromQL
// - the query contains two matchers within every selector - `{job=~"$job", instance=~"$instance"}`
// - the query is not empty
// - if the query references another panel then make sure that panel exists
func NewTargetPromQLRule() *TargetRuleFunc {
	return &TargetRuleFunc{
		name:        "target-promql-rule",
		description: "Checks that each target uses a valid PromQL query.",
		fn: func(d Dashboard, p Panel, t Target) TargetRuleResults {
			r := TargetRuleResults{}

			if t := getTemplateDatasource(d); t == nil || t.Query != Prometheus {
				// Missing template datasources is a separate rule.
				return r
			}

			if !panelHasQueries(p) {
				return r
			}

			// If panel does not contain an expression then check if it references another panel and it exists
			if len(t.Expr) == 0 {
				if t.PanelId > 0 {
					for _, p1 := range d.Panels {
						if p1.Id == t.PanelId {
							return r
						}
					}
					r.AddError(d, p, t, "Invalid panel reference in target")
				}
			}

			if _, err := parsePromQL(t.Expr, d.Templating.List); err != nil {
				r.AddError(d, p, t, fmt.Sprintf("invalid PromQL query '%s': %v", t.Expr, err))
			}

			return r
		},
	}
}
