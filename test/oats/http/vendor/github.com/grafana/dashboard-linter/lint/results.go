package lint

import (
	"fmt"
	"os"
	"sort"
)

var ResultSuccess = Result{
	Severity: Success,
	Message:  "OK",
}

type Result struct {
	Severity Severity
	Message  string
}

type FixableResult struct {
	Result
	Fix func(*Dashboard) // if nil, it cannot be fixed
}

type RuleResults struct {
	Results []FixableResult
}

type TargetResult struct {
	Result
	Fix func(Dashboard, Panel, *Target)
}

type TargetRuleResults struct {
	Results []TargetResult
}

func (r *TargetRuleResults) AddError(d Dashboard, p Panel, t Target, message string) {
	r.Results = append(r.Results, TargetResult{
		Result: Result{
			Severity: Error,
			Message:  fmt.Sprintf("Dashboard '%s', panel '%s', target idx '%d' %s", d.Title, p.Title, t.Idx, message),
		},
	})
}

type PanelResult struct {
	Result
	Fix func(Dashboard, *Panel)
}

type PanelRuleResults struct {
	Results []PanelResult
}

func (r *PanelRuleResults) AddError(d Dashboard, p Panel, message string) {
	msg := fmt.Sprintf("Dashboard '%s', panel '%s' %s", d.Title, p.Title, message)
	if p.Title == "" {
		msg = fmt.Sprintf("Dashboard '%s', panel with id '%d' %s", d.Title, p.Id, message)
	}

	r.Results = append(r.Results, PanelResult{
		Result: Result{
			Severity: Error,
			Message:  msg,
		},
	})
}

type DashboardResult struct {
	Result
	Fix func(*Dashboard)
}

type DashboardRuleResults struct {
	Results []DashboardResult
}

func dashboardMessage(d Dashboard, message string) string {
	return fmt.Sprintf("Dashboard '%s' %s", d.Title, message)
}

func (r *DashboardRuleResults) AddError(d Dashboard, message string) {
	r.Results = append(r.Results, DashboardResult{
		Result: Result{
			Severity: Error,
			Message:  dashboardMessage(d, message),
		},
	})
}

func (r *DashboardRuleResults) AddFixableError(d Dashboard, message string, fix func(*Dashboard)) {
	r.Results = append(r.Results, DashboardResult{
		Result: Result{
			Severity: Error,
			Message:  dashboardMessage(d, message),
		},
		Fix: fix,
	})
}

func (r *DashboardRuleResults) AddWarning(d Dashboard, message string) {
	r.Results = append(r.Results, DashboardResult{
		Result: Result{
			Severity: Warning,
			Message:  dashboardMessage(d, message),
		},
	})
}

// ResultContext is used by ResultSet to keep all the state data about a lint execution and it's results.
type ResultContext struct {
	Result    RuleResults
	Rule      Rule
	Dashboard *Dashboard
	Panel     *Panel
	Target    *Target
}

func (r Result) TtyPrint() {
	var sym string
	switch s := r.Severity; s {
	case Success:
		sym = "✔️"
	case Fixed:
		sym = "❌ (fixed)"
	case Exclude:
		sym = "➖"
	case Warning:
		sym = "⚠️"
	case Error:
		sym = "❌"
	case Quiet:
		return
	}

	fmt.Fprintf(os.Stdout, "[%s] %s\n", sym, r.Message)
}

type ResultSet struct {
	results []ResultContext
	config  *ConfigurationFile
}

// Configure adds, and applies the provided configuration to all results currently in the ResultSet
func (rs *ResultSet) Configure(c *ConfigurationFile) {
	rs.config = c
	for i := range rs.results {
		rs.results[i] = rs.config.Apply(rs.results[i])
	}
}

// AddResult adds a result to the ResultSet, applying the current configuration if set
func (rs *ResultSet) AddResult(r ResultContext) {
	if rs.config != nil {
		r = rs.config.Apply(r)
	}
	rs.results = append(rs.results, r)
}

func (rs *ResultSet) MaximumSeverity() Severity {
	retVal := Success
	for _, res := range rs.results {
		for _, r := range res.Result.Results {
			if r.Severity > retVal {
				retVal = r.Severity
			}
		}
	}
	return retVal
}

func (rs *ResultSet) ByRule() map[string][]ResultContext {
	ret := make(map[string][]ResultContext)
	for _, res := range rs.results {
		ret[res.Rule.Name()] = append(ret[res.Rule.Name()], res)
	}
	for _, rule := range ret {
		sort.SliceStable(rule, func(i, j int) bool {
			return rule[i].Dashboard.Title < rule[j].Dashboard.Title
		})
	}
	return ret
}

func (rs *ResultSet) ReportByRule() {
	byRule := rs.ByRule()
	rules := make([]string, 0, len(byRule))
	for r := range byRule {
		rules = append(rules, r)
	}
	sort.Strings(rules)

	for _, rule := range rules {
		fmt.Fprintln(os.Stdout, byRule[rule][0].Rule.Description())
		for _, rr := range byRule[rule] {
			for _, r := range rr.Result.Results {
				if r.Severity == Exclude && !rs.config.Verbose {
					continue
				}
				r.TtyPrint()
			}
		}
	}
}

func (rs *ResultSet) AutoFix(d *Dashboard) int {
	changes := 0
	for _, r := range rs.results {
		for i, fixableResult := range r.Result.Results {
			if fixableResult.Fix != nil {
				// Fix is only present when something can be fixed
				fixableResult.Fix(d)
				changes++
				r.Result.Results[i].Result.Severity = Fixed
			}
		}
	}
	return changes
}
