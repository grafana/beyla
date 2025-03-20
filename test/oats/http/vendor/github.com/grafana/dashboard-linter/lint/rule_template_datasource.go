package lint

import (
	"fmt"
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func NewTemplateDatasourceRule() *DashboardRuleFunc {
	return &DashboardRuleFunc{
		name:        "template-datasource-rule",
		description: "Checks that the dashboard has a templated datasource.",
		fn: func(d Dashboard) DashboardRuleResults {
			r := DashboardRuleResults{}

			templatedDs := d.GetTemplateByType("datasource")
			if len(templatedDs) == 0 {
				r.AddError(d, "does not have a templated data source")
			}

			// TODO: Should there be a "Template" rule type which will iterate over all dashboard templates and execute rules?
			// This will only return one linting error at a time, when there may be multiple issues with templated datasources.

			titleCaser := cases.Title(language.English)

			for _, templDs := range templatedDs {
				querySpecificUID := fmt.Sprintf("%s_datasource", strings.ToLower(templDs.Query))
				querySpecificName := fmt.Sprintf("%s data source", titleCaser.String(templDs.Query))

				allowedDsUIDs := make(map[string]struct{})
				allowedDsNames := make(map[string]struct{})

				uidError := fmt.Sprintf("templated data source variable named '%s', should be named '%s'", templDs.Name, querySpecificUID)
				nameError := fmt.Sprintf("templated data source variable labeled '%s', should be labeled '%s'", templDs.Label, querySpecificName)
				if len(templatedDs) == 1 {
					allowedDsUIDs["datasource"] = struct{}{}
					allowedDsNames["Data source"] = struct{}{}

					uidError += ", or 'datasource'"
					nameError += ", or 'Data source'"
				}

				allowedDsUIDs[querySpecificUID] = struct{}{}
				allowedDsNames[querySpecificName] = struct{}{}

				// TODO: These are really two different rules
				_, ok := allowedDsUIDs[templDs.Name]
				if !ok {
					r.AddError(d, uidError)
				}

				_, ok = allowedDsNames[templDs.Label]
				if !ok {
					r.AddWarning(d, nameError)
				}
			}

			return r
		},
	}
}

func getTemplateDatasource(d Dashboard) *Template {
	for _, template := range d.Templating.List {
		if template.Type != "datasource" {
			continue
		}
		return &template
	}
	return nil
}
