// Package jaeger provides some convenience data structures for integration testing.
// Disable some linting, as this is just a test class where readability is preferred to performance
// nolint:gocritic
package jaeger

type TracesQuery struct {
	Data []Trace `json:"data"`
}

type Trace struct {
	TraceID   string             `json:"traceID"`
	Spans     []Span             `json:"spans"`
	Processes map[string]Process `json:"processes"`
}

type Span struct {
	TraceID       string      `json:"traceID"`
	SpanID        string      `json:"spanID"`
	OperationName string      `json:"operationName"`
	References    []Reference `json:"references"`
	StartTime     int64       `json:"startTime"`
	Duration      int64       `json:"duration"`
	Tags          []Tag       `json:"tags"`
	ProcessID     string      `json:"processID"`
}

type Tag struct {
	Key   string      `json:"key"`
	Type  string      `json:"type"`
	Value interface{} `json:"value"`
}

type Reference struct {
	RefType string `json:"refType"`
	TraceID string `json:"traceID"`
	SpanID  string `json:"spanID"`
}

type Process struct {
	ServiceName string `json:"serviceName"`
	Tags        []Tag  `json:"tags"`
}

func (tq *TracesQuery) FindBySpan(tags ...Tag) []Trace {
	var matches []Trace
	for _, trace := range tq.Data {
		for _, span := range trace.Spans {
			if span.AllMatches(tags...) {
				matches = append(matches, trace)
				break
			}
		}
	}
	return matches
}

func (t *Trace) FindByOperationName(operationName string) []Span {
	var matches []Span
	for _, s := range t.Spans {
		if s.OperationName == operationName {
			matches = append(matches, s)
		}
	}
	return matches
}

func (t *Trace) ParentOf(s *Span) (Span, bool) {
	parentID := ""
	for _, ref := range s.References {
		if ref.RefType == "CHILD_OF" {
			parentID = ref.SpanID
		}
	}
	if parentID == "" {
		return Span{}, false
	}
	for _, sp := range t.Spans {
		if sp.SpanID == parentID {
			return sp, true
		}
	}
	return Span{}, false
}

func (t *Trace) ChildrenOf(parentID string) []Span {
	var matches []Span
	for _, sp := range t.Spans {
		for _, ref := range sp.References {
			if ref.RefType == "CHILD_OF" && ref.SpanID == parentID {
				matches = append(matches, sp)
				break
			}
		}
	}
	return matches
}

func (s *Span) AllMatches(tags ...Tag) bool {
	return AllMatches(s.Tags, tags)
}

func AllMatches(dst, src []Tag) bool {
	dstTags := map[Tag]struct{}{}
	for _, d := range dst {
		dstTags[d] = struct{}{}
	}

	for _, s := range src {
		if _, ok := dstTags[s]; !ok {
			return false
		}
	}
	return true
}
