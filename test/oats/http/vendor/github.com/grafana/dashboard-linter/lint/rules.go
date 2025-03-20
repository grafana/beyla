package lint

type Rule interface {
	Description() string
	Name() string
	Lint(Dashboard, *ResultSet)
}

type DashboardRuleFunc struct {
	name, description string
	fn                func(Dashboard) DashboardRuleResults
}

func NewDashboardRuleFunc(name, description string, fn func(Dashboard) DashboardRuleResults) Rule {
	return &DashboardRuleFunc{name, description, fn}
}

func (f DashboardRuleFunc) Name() string        { return f.name }
func (f DashboardRuleFunc) Description() string { return f.description }
func (f DashboardRuleFunc) Lint(d Dashboard, s *ResultSet) {
	dashboardResults := f.fn(d).Results
	if len(dashboardResults) == 0 {
		dashboardResults = []DashboardResult{{
			Result: ResultSuccess,
		}}
	}
	rr := make([]FixableResult, len(dashboardResults))
	for i, r := range dashboardResults {
		var fix func(*Dashboard)
		if r.Fix != nil {
			fix = func(dashboard *Dashboard) {
				r.Fix(dashboard)
			}
		}
		rr[i] = FixableResult{
			Result: Result{
				Severity: r.Severity,
				Message:  r.Message,
			},
			Fix: fix,
		}
	}

	s.AddResult(ResultContext{
		Result:    RuleResults{rr},
		Rule:      f,
		Dashboard: &d,
	})
}

type PanelRuleFunc struct {
	name, description string
	fn                func(Dashboard, Panel) PanelRuleResults
}

func NewPanelRuleFunc(name, description string, fn func(Dashboard, Panel) PanelRuleResults) Rule {
	return &PanelRuleFunc{name, description, fn}
}

func (f PanelRuleFunc) Name() string        { return f.name }
func (f PanelRuleFunc) Description() string { return f.description }
func (f PanelRuleFunc) Lint(d Dashboard, s *ResultSet) {
	for pi, p := range d.GetPanels() {
		p := p   // capture loop variable
		pi := pi // capture loop variable
		var rr []FixableResult

		panelResults := f.fn(d, p).Results
		if len(panelResults) == 0 {
			panelResults = []PanelResult{{
				Result: ResultSuccess,
			}}
		}

		for _, r := range panelResults {
			var fix func(*Dashboard)
			if r.Fix != nil {
				fix = fixPanel(pi, r)
			}
			rr = append(rr, FixableResult{
				Result: Result{
					Severity: r.Severity,
					Message:  r.Message,
				},
				Fix: fix,
			})
		}

		s.AddResult(ResultContext{
			Result:    RuleResults{rr},
			Rule:      f,
			Dashboard: &d,
			Panel:     &p,
		})
	}
}

func fixPanel(pi int, r PanelResult) func(dashboard *Dashboard) {
	return func(dashboard *Dashboard) {
		p := dashboard.GetPanels()[pi]
		r.Fix(*dashboard, &p)
		dashboard.Panels[pi] = p
	}
}

type TargetRuleFunc struct {
	name, description string
	fn                func(Dashboard, Panel, Target) TargetRuleResults
}

func NewTargetRuleFunc(name, description string, fn func(Dashboard, Panel, Target) TargetRuleResults) Rule {
	return &TargetRuleFunc{name, description, fn}
}

func (f TargetRuleFunc) Name() string        { return f.name }
func (f TargetRuleFunc) Description() string { return f.description }
func (f TargetRuleFunc) Lint(d Dashboard, s *ResultSet) {
	for pi, p := range d.GetPanels() {
		p := p   // capture loop variable
		pi := pi // capture loop variable
		for ti, t := range p.Targets {
			t := t   // capture loop variable
			ti := ti // capture loop variable
			var rr []FixableResult

			targetResults := f.fn(d, p, t).Results
			if len(targetResults) == 0 {
				targetResults = []TargetResult{{
					Result: ResultSuccess,
				}}
			}

			for _, r := range targetResults {
				var fix func(*Dashboard)
				if r.Fix != nil {
					fix = fixTarget(pi, ti, r)
				}
				rr = append(rr, FixableResult{
					Result: Result{
						Severity: r.Severity,
						Message:  r.Message,
					},
					Fix: fix,
				})
			}
			s.AddResult(ResultContext{
				Result:    RuleResults{rr},
				Rule:      f,
				Dashboard: &d,
				Panel:     &p,
				Target:    &t,
			})
		}
	}
}

func fixTarget(pi int, ti int, r TargetResult) func(dashboard *Dashboard) {
	return func(dashboard *Dashboard) {
		p := dashboard.GetPanels()[pi]
		t := p.Targets[ti]
		r.Fix(*dashboard, p, &t)
		p.Targets[ti] = t
		dashboard.Panels[pi] = p
	}
}

// RuleSet contains a list of linting rules.
type RuleSet struct {
	rules []Rule
}

func NewRuleSet() RuleSet {
	return RuleSet{
		rules: []Rule{
			NewTemplateDatasourceRule(),
			NewTemplateJobRule(),
			NewTemplateInstanceRule(),
			NewTemplateLabelPromQLRule(),
			NewTemplateOnTimeRangeReloadRule(),
			NewPanelDatasourceRule(),
			NewPanelTitleDescriptionRule(),
			NewPanelUnitsRule(),
			NewPanelNoTargetsRule(),
			NewTargetPromQLRule(),
			NewTargetRateIntervalRule(),
			NewTargetJobRule(),
			NewTargetInstanceRule(),
			NewTargetCounterAggRule(),
		},
	}
}

func (s *RuleSet) Rules() []Rule {
	return s.rules
}

func (s *RuleSet) Add(r Rule) {
	s.rules = append(s.rules, r)
}

func (s *RuleSet) Lint(dashboards []Dashboard) (*ResultSet, error) {
	resSet := &ResultSet{}
	for _, d := range dashboards {
		for _, r := range s.rules {
			r.Lint(d, resSet)
		}
	}
	return resSet, nil
}
