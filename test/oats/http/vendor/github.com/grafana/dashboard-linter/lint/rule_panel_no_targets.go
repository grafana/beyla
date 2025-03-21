package lint

func NewPanelNoTargetsRule() *PanelRuleFunc {
	return &PanelRuleFunc{
		name:        "panel-no-targets-rule",
		description: "Checks that each panel has at least one target.",
		fn: func(d Dashboard, p Panel) PanelRuleResults {
			r := PanelRuleResults{}
			switch p.Type {
			case panelTypeStat, panelTypeSingleStat, panelTypeGraph, panelTypeTimeTable, panelTypeTimeSeries, panelTypeGauge:
				if p.Targets != nil {
					return r
				}

				r.AddError(d, p, "has no targets")
			}
			return r
		},
	}
}
