package lint

import (
	"fmt"
	"regexp"
)

var templatedLabelRegexp = regexp.MustCompile(`([a-z_]+)\((.+)\)`)

func labelHasValidDataSourceFunction(name string) bool {
	// https://grafana.com/docs/grafana/v8.1/datasources/prometheus/#query-variable
	names := []string{"label_names", "label_values", "metrics", "query_result"}
	for _, n := range names {
		if name == n {
			return true
		}
	}
	return false
}

// parseTemplatedLabelPromQL returns error in case
// 1) The given PromQL expressions is invalid
// 2) Use of invalid label function
func parseTemplatedLabelPromQL(t Template, variables []Template) error {
	// regex capture must return slice of 3 strings.
	// 1) given query 2) function name 3) function arg.
	tokens := templatedLabelRegexp.FindStringSubmatch(t.Query)
	if tokens == nil {
		return fmt.Errorf("invalid 'query': %v", t.Query)
	}

	if !labelHasValidDataSourceFunction(tokens[1]) {
		return fmt.Errorf("invalid 'function': %v", tokens[1])
	}
	expr, err := parsePromQL(tokens[2], variables)
	if expr != nil {
		return nil
	}
	return err
}

func NewTemplateLabelPromQLRule() *DashboardRuleFunc {
	return &DashboardRuleFunc{
		name:        "template-label-promql-rule",
		description: "Checks that the dashboard templated labels have proper PromQL expressions.",
		fn: func(d Dashboard) DashboardRuleResults {
			r := DashboardRuleResults{}

			template := getTemplateDatasource(d)
			if template == nil || template.Query != Prometheus {
				return r
			}
			for _, template := range d.Templating.List {
				if template.Type != targetTypeQuery {
					continue
				}
				if err := parseTemplatedLabelPromQL(template, d.Templating.List); err != nil {
					r.AddError(d, fmt.Sprintf("template '%s' invalid templated label '%s': %v", template.Name, template.Query, err))
				}
			}

			return r
		},
	}
}
