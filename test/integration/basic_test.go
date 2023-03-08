//go:build integration

package integration

import (
	"fmt"
	"math/rand"
	"net/http"
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
	instrumentedServiceURL = "http://localhost:8080"
	prometheusHostPort     = "localhost:9090"

	testTimeout = 5 * time.Second
)

func rndStr() string {
	return strconv.Itoa(rand.Intn(10000))
}

func waitForTestService() {
	slog.Debug("waiting for instrumented service to be up and running")
	limit := time.Now().Add(testTimeout)
	for {
		if resp, err := http.Get(instrumentedServiceURL); err == nil && resp.StatusCode == http.StatusOK {
			return
		}
		if time.Now().After(limit) {
			panic("timeout while waiting for instrumented service to be up and running")
		}
	}
}

func TestMain(m *testing.M) {
	waitForTestService()
	m.Run()
}

func TestBasic(t *testing.T) {
	path := "/basic/" + rndStr()

	// Call 3 times the instrumented service, forcing it to:
	// - take at least 30ms to respond
	// - returning a 404 code
	for i := 0; i < 3; i++ {
		r, err := http.Get(instrumentedServiceURL + path + "?delay=30ms&status=404")
		require.NoError(t, err)
		require.Equal(t, 404, r.StatusCode)
	}

	// Eventually, Prometheus would make this query visible
	pq := prom.Client{HostPort: prometheusHostPort}
	var results []prom.Result
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		var err error
		results, err = pq.Query(`duration_count{http_target="` + path + `"}`)
		require.NoError(t, err)
		require.NotEmpty(t, results)
	})

	// check duration_count has 3 calls and all the arguments
	assert.Len(t, results, 1)
	res := results[0]
	assert.Equal(t, "GET", res.Metric["http_method"])
	assert.Equal(t, "404", res.Metric["http_status_code"])
	assert.Equal(t, path, res.Metric["http_target"])
	assert.Equal(t, "/testserver", res.Metric["service_name"])
	require.Len(t, res.Value, 2)
	assert.Equal(t, "3", res.Value[1])

	// check duration_sum is at least 90ms (3 * 30ms)
	var err error
	results, err = pq.Query(`duration_sum{http_target="` + path + `"}`)
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Len(t, results, 1)
	res = results[0]
	assert.Equal(t, "GET", res.Metric["http_method"])
	assert.Equal(t, "404", res.Metric["http_status_code"])
	assert.Equal(t, path, res.Metric["http_target"])
	assert.Equal(t, "/testserver", res.Metric["service_name"])
	require.Len(t, res.Value, 2)
	sum, err := strconv.ParseFloat(fmt.Sprint(res.Value[1]), 64)
	require.NoError(t, err)
	assert.Greater(t, sum, 90.0)
}
