package process

type CriteriaMatcher struct{}

type ExecutableTyper struct{}

type TraceAttacher struct{}

type Finder struct {
	Watcher         `sendTo:"CriteriaMatcher"`
	CriteriaMatcher `sendTo:"ExecutableTyper"`
	ExecutableTyper `sendTo:"TraceAttacher"`
	TraceAttacher
}
