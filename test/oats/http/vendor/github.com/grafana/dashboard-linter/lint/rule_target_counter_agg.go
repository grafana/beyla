package lint

import (
	"fmt"
	"strings"

	"github.com/prometheus/prometheus/promql/parser"
)

func NewTargetCounterAggRule() *TargetRuleFunc {
	return &TargetRuleFunc{
		name:        "target-counter-agg-rule",
		description: "Checks that any counter metric (ending in _total) is aggregated with rate, irate, or increase.",
		fn: func(d Dashboard, p Panel, t Target) TargetRuleResults {
			r := TargetRuleResults{}
			expr, err := parsePromQL(t.Expr, d.Templating.List)
			if err != nil {
				// Invalid PromQL is another rule
				return r
			}

			err = parser.Walk(newInspector(), expr, nil)
			if err != nil {
				r.AddError(d, p, t, err.Error())
			}
			return r
		},
	}
}

func newInspector() inspector {
	return func(node parser.Node, parents []parser.Node) error {
		// We're looking for either a VectorSelector. This skips any other node type.
		selector, ok := node.(*parser.VectorSelector)
		if !ok {
			return nil
		}

		errmsg := fmt.Errorf("counter metric '%s' is not aggregated with rate, irate, or increase", node.String())

		if strings.HasSuffix(selector.String(), "_total") {
			// The vector selector must have (at least) two parents
			if len(parents) < 2 {
				return errmsg
			}
			// The vector must be ranged
			_, ok := parents[len(parents)-1].(*parser.MatrixSelector)
			if !ok {
				return errmsg
			}
			// The range, must be in a function call
			call, ok := parents[len(parents)-2].(*parser.Call)
			if !ok {
				return errmsg
			}
			// Finally, the immediate ancestor call must be rate, irate, or increase
			if call.Func.Name != "rate" && call.Func.Name != "irate" && call.Func.Name != "increase" {
				return errmsg
			}
		}
		return nil
	}
}
