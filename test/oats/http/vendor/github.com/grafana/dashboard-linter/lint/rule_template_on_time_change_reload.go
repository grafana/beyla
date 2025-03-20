package lint

import (
	"fmt"
)

func NewTemplateOnTimeRangeReloadRule() *DashboardRuleFunc {
	return &DashboardRuleFunc{
		name:        "template-on-time-change-reload-rule",
		description: "Checks that the dashboard template variables are configured to reload on time change.",
		fn: func(d Dashboard) DashboardRuleResults {
			r := DashboardRuleResults{}

			for i, template := range d.Templating.List {
				if template.Type != targetTypeQuery {
					continue
				}

				if template.Refresh != 2 {
					r.AddFixableError(d,
						fmt.Sprintf("templated datasource variable named '%s', should be set to be refreshed "+
							"'On Time Range Change (value 2)', is currently '%d'", template.Name, template.Refresh),
						fixTemplateOnTimeRangeReloadRule(i))
				}
			}
			return r
		},
	}
}

func fixTemplateOnTimeRangeReloadRule(i int) func(*Dashboard) {
	return func(d *Dashboard) {
		d.Templating.List[i].Refresh = 2
	}
}
