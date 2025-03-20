package lint

import (
	"fmt"
	"time"

	"github.com/prometheus/prometheus/promql/parser"
)

type inspector func(parser.Node, []parser.Node) error

func (f inspector) Visit(node parser.Node, path []parser.Node) (parser.Visitor, error) {
	if err := f(node, path); err != nil {
		return nil, err
	}
	return f, nil
}

// NewTargetRateIntervalRule builds a lint rule for panels with Prometheus queries which checks
// all range vector selectors use $__rate_interval.
func NewTargetRateIntervalRule() *TargetRuleFunc {
	rateIntervalMagicDuration, err := time.ParseDuration(globalVariables["__rate_interval"].(string))
	if err != nil {
		// Will not happen
		panic(err)
	}
	return &TargetRuleFunc{
		name:        "target-rate-interval-rule",
		description: "Checks that each target uses $__rate_interval.",
		fn: func(d Dashboard, p Panel, t Target) TargetRuleResults {
			r := TargetRuleResults{}
			if t := getTemplateDatasource(d); t == nil || t.Query != Prometheus {
				// Missing template datasources is a separate rule.
				return r
			}

			if !panelHasQueries(p) {
				// Don't lint certain types of panels.
				return r
			}

			expr, err := parsePromQL(t.Expr, d.Templating.List)
			if err != nil {
				// Invalid PromQL is another rule
				return r
			}
			err = parser.Walk(inspector(func(node parser.Node, parents []parser.Node) error {
				selector, ok := node.(*parser.MatrixSelector)
				if !ok {
					// We are not inspecting something like foo{...}[...]
					return nil
				}

				if selector.Range == rateIntervalMagicDuration {
					// Range vector selector is $__rate_interval
					return nil
				}

				if len(parents) == 0 {
					// Bit weird to have a naked foo[$__rate_interval], but allow it.
					return nil
				}
				// Now check if the parent is a rate function
				call, ok := parents[len(parents)-1].(*parser.Call)
				if !ok {
					return fmt.Errorf(
						"invalid PromQL query '%s': $__rate_interval used in non-rate function", t.Expr)
				}

				if call.Func.Name != "rate" && call.Func.Name != "irate" {
					// the parent is not an (i)rate function call, allow it
					return nil
				}

				return fmt.Errorf("invalid PromQL query '%s': should use $__rate_interval", t.Expr)
			}), expr, nil)
			if err != nil {
				r.AddError(d, p, t, err.Error())
			}

			return r
		},
	}
}
