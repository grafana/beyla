package yaml

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/grafana/regexp"

	"github.com/grafana/oats/testhelpers/compose"
	"github.com/grafana/oats/testhelpers/requests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type runner struct {
	testCase    *TestCase
	endpoint    *compose.ComposeEndpoint
	deadline    time.Time
	queryLogger QueryLogger
	gomega      Gomega
}

var VerboseLogging bool

func RunTestCase(c *TestCase) {
	r := &runner{
		testCase: c,
	}

	BeforeAll(func() {
		c.OutputDir = prepareBuildDir(c.Name)
		c.validateAndSetVariables()
		endpoint := c.startEndpoint()

		r.deadline = time.Now().Add(c.Timeout)
		r.endpoint = endpoint
		if os.Getenv("TESTCASE_MANUAL_DEBUG") == "true" {
			GinkgoWriter.Printf("stopping to let you manually debug on http://localhost:%d\n", r.testCase.PortConfig.GrafanaHTTPPort)

			for {
				r.eventually(func() {
					// do nothing - just feed input into the application
				})
				time.Sleep(1 * time.Second)
			}
		}

		GinkgoWriter.Printf("deadline = %v\n", r.deadline)
	})

	AfterAll(func() {
		var ctx = context.Background()
		var stopErr error

		if r.endpoint != nil {
			stopErr = r.endpoint.Stop(ctx)
			Expect(stopErr).ToNot(HaveOccurred(), "expected no error stopping the local observability endpoint")
		}
	})

	expected := c.Definition.Expected
	// Assert logs traces first, because metrics and dashboards can take longer to appear
	// (depending on OTEL_METRIC_EXPORT_INTERVAL).
	for _, log := range expected.Logs {
		l := log
		if r.MatchesMatrixCondition(l.MatrixCondition, l.LogQL) {
			It(fmt.Sprintf("should have '%s' in loki", l), func() {
				r.eventually(func() {
					AssertLoki(r, l)
				})
			})
		}
	}
	for _, trace := range expected.Traces {
		t := trace
		if r.MatchesMatrixCondition(t.MatrixCondition, t.TraceQL) {
			It(fmt.Sprintf("should have '%s' in tempo", t.TraceQL), func() {
				r.eventually(func() {
					AssertTempo(r, t)
				})
			})
		}
	}
	for _, dashboard := range expected.Dashboards {
		dashboardAssert := NewDashboardAssert(dashboard)
		for i, panel := range dashboard.Panels {
			iCopy := i
			p := panel
			if r.MatchesMatrixCondition(p.MatrixCondition, p.Title) {
				It(fmt.Sprintf("dashboard panel '%s'", p.Title), func() {
					r.eventually(func() {
						dashboardAssert.AssertDashboard(r, iCopy)
					})
				})
			}
		}
	}
	for _, metric := range expected.Metrics {
		m := metric
		if r.MatchesMatrixCondition(m.MatrixCondition, m.PromQL) {
			It(fmt.Sprintf("should have '%s' in prometheus", m.PromQL), func() {
				r.eventually(func() {
					AssertProm(r, m.PromQL, m.Value)
				})
			})
		}
	}
}

func (c *TestCase) startEndpoint() *compose.ComposeEndpoint {
	var ctx = context.Background()

	GinkgoWriter.Printf("Launching test for %s\n", c.Name)

	endpoint := compose.NewEndpoint(
		c.CreateDockerComposeFile(),
		filepath.Join(c.OutputDir, fmt.Sprintf("output-%s.log", c.Name)),
		[]string{},
		compose.PortsConfig{
			PrometheusHTTPPort: c.PortConfig.PrometheusHTTPPort,
			TempoHTTPPort:      c.PortConfig.TempoHTTPPort,
			LokiHttpPort:       c.PortConfig.LokiHTTPPort,
		},
	)
	startErr := endpoint.Start(ctx)
	Expect(startErr).ToNot(HaveOccurred(), "expected no error starting a local observability endpoint")
	return endpoint
}

func prepareBuildDir(name string) string {
	dir := filepath.Join(".", "build", name)

	fileinfo, err := os.Stat(dir)
	if err == nil {
		if fileinfo.IsDir() {
			err := os.RemoveAll(dir)
			Expect(err).ToNot(HaveOccurred(), "expected no error removing output directory")
		}
	}
	err = os.MkdirAll(dir, 0755)
	Expect(err).ToNot(HaveOccurred(), "expected no error creating output directory")
	return dir
}

func (r *runner) eventually(asserter func()) {
	if r.deadline.Before(time.Now()) {
		Fail("deadline exceeded waiting for telemetry")
	}
	t := time.Now()
	ctx := context.Background()
	interval := r.testCase.Definition.Interval
	if interval == 0 {
		interval = DefaultTestCaseInterval
	}
	iterations := 0
	Eventually(ctx, func(g Gomega) {
		iterations++
		verbose := VerboseLogging
		if time.Since(t) > 10*time.Second {
			verbose = true
			t = time.Now()
		}
		queryLogger := NewQueryLogger(r.endpoint, verbose)
		queryLogger.LogQueryResult("waiting for telemetry data\n")

		for _, i := range r.testCase.Definition.Input {
			url := fmt.Sprintf("http://localhost:%d%s", r.testCase.PortConfig.ApplicationPort, i.Path)
			status := 200
			if i.Status != "" {
				parsedStatus, err := strconv.ParseInt(i.Status, 10, 64)
				if err == nil {
					status = int(parsedStatus)
				}
			}
			err := requests.DoHTTPGet(url, status)
			g.Expect(err).ToNot(HaveOccurred(), "expected no error calling application endpoint %s", url)
		}

		r.queryLogger = queryLogger
		r.gomega = g
		asserter()
	}).WithTimeout(r.deadline.Sub(time.Now())).WithPolling(interval).Should(Succeed(), "calling application for %v should cause telemetry to appear", r.testCase.Timeout)
	GinkgoWriter.Println(iterations, "iterations to get telemetry data")
}

func (r *runner) MatchesMatrixCondition(matrixCondition string, subject string) bool {
	if matrixCondition == "" {
		return true
	}
	name := r.testCase.MatrixTestCaseName
	if name == "" {
		r.queryLogger.LogQueryResult("matrix condition %v ignored we're not in a matrix test\n", matrixCondition)
		return true
	}
	if regexp.MustCompile(matrixCondition).MatchString(name) {
		return true
	}
	fmt.Printf("matrix condition not matched - ignoring assertion: %v/%v/%v\n", r.testCase.Name, name, subject)
	return false
}
