package lint

import (
	"fmt"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func NewTemplateJobRule() *DashboardRuleFunc {
	return &DashboardRuleFunc{
		name:        "template-job-rule",
		description: "Checks that the dashboard has a templated job.",
		fn: func(d Dashboard) DashboardRuleResults {
			r := DashboardRuleResults{}

			template := getTemplateDatasource(d)
			if template == nil || template.Query != Prometheus {
				return r
			}

			checkTemplate(d, "job", &r)
			return r
		},
	}
}

func checkTemplate(d Dashboard, name string, r *DashboardRuleResults) {
	t := getTemplate(d, name)
	if t == nil {
		r.AddError(d, fmt.Sprintf("is missing the %s template", name))
		return
	}

	// TODO: Adding the prometheus_datasource here is hacky. This check function also assumes that all template vars which it will
	// ever check are only prometheus queries, which may not always be the case.
	src, err := t.GetDataSource()
	if err != nil {
		r.AddError(d, fmt.Sprintf("%s template has invalid datasource %v", name, err))
	}

	if src != "$datasource" && src != "${datasource}" && src != "$prometheus_datasource" && src != "${prometheus_datasource}" {
		r.AddError(d, fmt.Sprintf("%s template should use datasource '$datasource', is currently '%s'", name, src))
	}

	if t.Type != targetTypeQuery {
		r.AddError(d, fmt.Sprintf("%s template should be a Prometheus query, is currently '%s'", name, t.Type))
	}

	titleCaser := cases.Title(language.English)
	labelTitle := titleCaser.String(name)

	if t.Label != labelTitle {
		r.AddWarning(d, fmt.Sprintf("%s template should be a labeled '%s', is currently '%s'", name, labelTitle, t.Label))
	}

	if !t.Multi {
		r.AddError(d, fmt.Sprintf("%s template should be a multi select", name))
	}

	if t.AllValue != ".+" {
		r.AddError(d, fmt.Sprintf("%s template allValue should be '.+', is currently '%s'", name, t.AllValue))
	}
}

func getTemplate(d Dashboard, name string) *Template {
	for _, template := range d.Templating.List {
		if template.Name == name {
			return &template
		}
	}
	return nil
}
