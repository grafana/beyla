package lint

import "fmt"

func NewPanelTitleDescriptionRule() *PanelRuleFunc {
	return &PanelRuleFunc{
		name:        "panel-title-description-rule",
		description: "Checks that each panel has a title and description.",
		fn: func(d Dashboard, p Panel) PanelRuleResults {
			r := PanelRuleResults{}
			switch p.Type {
			case panelTypeStat, panelTypeSingleStat, panelTypeGraph, panelTypeTimeTable, panelTypeTimeSeries, panelTypeGauge:
				if len(p.Title) == 0 || len(p.Description) == 0 {
					r.AddError(d, p, fmt.Sprintf("has missing title or description, currently has title '%s' and description: '%s'", p.Title, p.Description))
				}
			}
			return r
		},
	}
}
