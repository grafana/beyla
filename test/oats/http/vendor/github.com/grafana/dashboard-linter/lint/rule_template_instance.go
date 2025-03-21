package lint

func NewTemplateInstanceRule() *DashboardRuleFunc {
	return &DashboardRuleFunc{
		name:        "template-instance-rule",
		description: "Checks that the dashboard has a templated instance.",
		fn: func(d Dashboard) DashboardRuleResults {
			r := DashboardRuleResults{}

			template := getTemplateDatasource(d)
			if template == nil || template.Query != Prometheus {
				return r
			}

			checkTemplate(d, "instance", &r)
			return r
		},
	}
}
