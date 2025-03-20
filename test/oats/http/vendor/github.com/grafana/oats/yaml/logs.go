package yaml

import (
	. "github.com/onsi/gomega"
)

func AssertLoki(r *runner, l ExpectedLogs) {
	b, err := r.endpoint.SearchLoki(l.LogQL)
	r.queryLogger.LogQueryResult("logQL query %v response %v err=%v\n", l.LogQL, string(b), err)
	g := r.gomega
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(len(b)).Should(BeNumerically(">", 0), "expected loki response to be non-empty")

	for _, s := range l.Contains {
		g.Expect(string(b)).To(ContainSubstring(s))
	}
}
