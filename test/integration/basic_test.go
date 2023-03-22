//go:build integration

package integration

import (
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"testing"
	"time"

	"golang.org/x/exp/slog"

	"github.com/grafana/http-autoinstrument/test/integration/components/prom"
	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	instrumentedServiceStdURL     = "http://localhost:8080"
	instrumentedServiceGinURL     = "http://localhost:8081"
	instrumentedServiceGorillaURL = "http://localhost:8082"
	prometheusHostPort            = "localhost:9090"

	testTimeout = 5 * time.Second
)

func rndStr() string {
	return strconv.Itoa(rand.Intn(10000))
}

func waitForTestService(url string) {
	slog.Debug("waiting for instrumented service to be up and running")
	limit := time.Now().Add(testTimeout)
	for {
		if resp, err := http.Get(url); err == nil && resp.StatusCode == http.StatusOK {
			return
		}
		if time.Now().After(limit) {
			panic("timeout while waiting for instrumented service to be up and running")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestMain(m *testing.M) {
	waitForTestService(instrumentedServiceStdURL)
	waitForTestService(instrumentedServiceGinURL)
	waitForTestService(instrumentedServiceGorillaURL)
	m.Run()
}

func TestBasic(t *testing.T) {
	for _, testCaseURL := range []string{
		instrumentedServiceStdURL,
		instrumentedServiceGorillaURL,
		instrumentedServiceGinURL,
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			basicTest(t, testCaseURL)
		})
	}
}

func basicTest(t *testing.T, url string) {
	path := "/basic/" + rndStr()
	digits := regexp.MustCompile(`[0-9]+`)

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 404 code
	for i := 0; i < 3; i++ {
		r, err := http.Get(url + path + "?delay=30ms&status=404")
		require.NoError(t, err)
		require.Equal(t, 404, r.StatusCode)
		time.Sleep(300 * time.Millisecond)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`duration_count{` +
			`http_method="GET",` +
			`http_status_code="404",` +
			`service_name="/testserver",` +
			`http_target="` + path + `"}`)
		require.NoError(t, err)
		// check duration_count has 3 calls and all the arguments
		require.Len(t, results, 1)
		if len(results) > 0 {
			res := results[0]
			require.Len(t, res.Value, 2)
			assert.Equal(t, "3", res.Value[1])
			addr := net.ParseIP(res.Metric["net_peer_name"])
			assert.NotNil(t, addr)
			assert.True(t, digits.MatchString(res.Metric["net_peer_port"]))
		}
	})

	// check duration_sum is at least 90ms (3 * 30ms)
	var err error
	results, err = pq.Query(`duration_sum{` +
		`http_method="GET",` +
		`http_status_code="404",` +
		`service_name="/testserver",` +
		`http_target="` + path + `"}`)
	require.NoError(t, err)
	require.Len(t, results, 1)
	res := results[0]
	require.Len(t, res.Value, 2)
	sum, err := strconv.ParseFloat(fmt.Sprint(res.Value[1]), 64)
	require.NoError(t, err)
	assert.Greater(t, sum, 90.0)
	addr := net.ParseIP(res.Metric["net_peer_name"])
	assert.NotNil(t, addr)
	assert.True(t, digits.MatchString(res.Metric["net_peer_port"]))
}
