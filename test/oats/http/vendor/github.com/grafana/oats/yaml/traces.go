package yaml

import (
	"context"

	"github.com/grafana/oats/testhelpers/tempo/responses"
	. "github.com/onsi/gomega"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

func AssertTempo(r *runner, t ExpectedTraces) {
	ctx := context.Background()

	b, err := r.endpoint.SearchTempo(ctx, t.TraceQL)
	r.queryLogger.LogQueryResult("traceQL query %v response %v err=%v\n", t.TraceQL, string(b), err)
	g := r.gomega
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(len(b)).Should(BeNumerically(">", 0))

	res, err := responses.ParseTempoSearchResult(b)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(res.Traces).ToNot(BeEmpty())

	assertTrace(r, res.Traces[0], t.Spans)
}

func assertTrace(r *runner, tr responses.Trace, wantSpans []ExpectedSpan) {
	ctx := context.Background()

	b, err := r.endpoint.GetTraceByID(ctx, tr.TraceID)
	r.queryLogger.LogQueryResult("traceQL traceID %v response %v err=%v\n", tr.TraceID, string(b), err)

	g := r.gomega
	g.Expect(err).ToNot(HaveOccurred(), "we should find the trace by traceID")
	g.Expect(len(b)).Should(BeNumerically(">", 0))

	td, err := responses.ParseTraceDetails(b)
	g.Expect(err).ToNot(HaveOccurred(), "we should be able to parse the GET trace by traceID API output")

	for _, wantSpan := range wantSpans {
		spans, atts := responses.FindSpansWithAttributes(td, wantSpan.Name)
		if wantSpan.AllowDups {
			g.Expect(len(spans)).Should(BeNumerically(">", 0), "we should find at least one span with the name %s", wantSpan.Name)
		} else {
			g.Expect(spans).To(HaveLen(1), "we should find a single span with the name %s", wantSpan.Name)
		}

		for k, v := range wantSpan.Attributes {
			for k, v := range spans[0].Attributes().AsRaw() {
				atts[k] = v
			}
			m := pcommon.NewMap()
			err = m.FromRaw(atts)
			g.Expect(err).ToNot(HaveOccurred(), "we should be able to convert the map to a pdata.Map")
			err := responses.MatchTraceAttribute(m, pcommon.ValueTypeStr, k, v)
			g.Expect(err).ToNot(HaveOccurred(), "span attribute should match")
		}
	}
}
