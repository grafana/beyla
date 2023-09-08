//go:build integration

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/goccy/go-json"
	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/test/integration/components/jaeger"
	grpcclient "github.com/grafana/beyla/test/integration/components/testserver/grpc/client"
)

func testHTTPTracesNoTraceID(t *testing.T) {
	testHTTPTracesCommon(t, false)
}

func testHTTPTraces(t *testing.T) {
	testHTTPTracesCommon(t, true)
}

func testHTTPTracesCommon(t *testing.T, doTraceID bool) {
	var traceID string
	var parentID string

	slug := "create-trace"
	if doTraceID {
		slug = "create-trace-with-id"
		// Add and check for specific trace ID
		traceID = createTraceID()
		parentID = createParentID()
		traceparent := createTraceparent(traceID, parentID)
		doHTTPGetWithTraceparent(t, instrumentedServiceStdURL+"/"+slug+"?delay=10ms", 200, traceparent)
	} else {
		doHTTPGet(t, instrumentedServiceStdURL+"/"+slug+"?delay=10ms", 200)
	}

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2F" + slug)
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "http.target", Type: "string", Value: "/" + slug})
		require.Len(t, traces, 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the parent span
	res := trace.FindByOperationName("GET /" + slug)
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	if doTraceID {
		require.Equal(t, traceID, parent.TraceID)
		// Validate that "parent" is a CHILD_OF the traceparent's "parent-id"
		childOfPID := trace.ChildrenOf(parentID)
		require.Len(t, childOfPID, 1)
	}
	require.NotEmpty(t, parent.SpanID)
	// check duration is at least 10ms
	assert.Less(t, (10 * time.Millisecond).Microseconds(), parent.Duration)
	// check span attributes
	assert.Truef(t, parent.AllMatches(
		jaeger.Tag{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		jaeger.Tag{Key: "http.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.status_code", Type: "int64", Value: float64(200)},
		jaeger.Tag{Key: "http.target", Type: "string", Value: "/" + slug},
		jaeger.Tag{Key: "net.host.port", Type: "int64", Value: float64(8080)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/" + slug},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	), "not all tags matched in %+v", parent.Tags)

	// Check the information of the "in queue" span
	res = trace.FindByOperationName("in queue")
	require.Len(t, res, 1)
	queue := res[0]
	// Check parenthood
	p, ok := trace.ParentOf(&queue)
	require.True(t, ok)
	assert.Equal(t, parent.TraceID, p.TraceID)
	assert.Equal(t, parent.SpanID, p.SpanID)
	// check reasonable start and end times
	assert.GreaterOrEqual(t, queue.StartTime, parent.StartTime)
	assert.LessOrEqual(t,
		queue.StartTime+queue.Duration,
		parent.StartTime+parent.Duration+1) // adding 1 to tolerate inaccuracies from rounding from ns to ms
	// check span attributes
	// check span attributes
	assert.Truef(t, queue.AllMatches(
		jaeger.Tag{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	), "not all tags matched in %+v", queue.Tags)

	// Check the information of the "processing" span
	res = trace.FindByOperationName("processing")
	require.Len(t, res, 1)
	processing := res[0]
	// Check parenthood
	p, ok = trace.ParentOf(&queue)
	require.True(t, ok)
	assert.Equal(t, parent.TraceID, p.TraceID)
	assert.Equal(t, parent.SpanID, p.SpanID)
	// check reasonable start and end times
	assert.GreaterOrEqual(t, processing.StartTime, queue.StartTime+queue.Duration)
	assert.LessOrEqual(t,
		processing.StartTime+processing.Duration,
		parent.StartTime+parent.Duration+1)
	assert.Truef(t, queue.AllMatches(
		jaeger.Tag{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	), "not all tags matched in %+v", queue.Tags)

	// check process ID
	require.Contains(t, trace.Processes, parent.ProcessID)
	assert.Equal(t, parent.ProcessID, queue.ProcessID)
	assert.Equal(t, parent.ProcessID, processing.ProcessID)
	process := trace.Processes[parent.ProcessID]
	assert.Equal(t, "testserver", process.ServiceName)
	assert.Truef(t, jaeger.AllMatches(process.Tags, []jaeger.Tag{
		{Key: "telemetry.sdk.language", Type: "string", Value: "go"},
		{Key: "service.namespace", Type: "string", Value: "integration-test"},
	}), "not all tags matched in %+v", process.Tags)
}

func testHTTPTracesBadTraceparent(t *testing.T) {
	slugToParent := map[string]string{
		// Valid traceparent example:
		//		valid: "00-5fe865607da112abd799ea8108c38bcb-4c59e9a913c480a3-01"
		// Examples of INVALID traceIDs in traceparent:  Note: eBPF rejects when len != 55
		"invalid-trace-id1": "00-Zfe865607da112abd799ea8108c38bcb-4c59e9a913c480a3-01",
		"invalid-trace-id2": "00-5fe865607da112abd799ea8108c38bcL-4c59e9a913c480a3-01",
		"invalid-trace-id3": "00-5fe865607Ra112abd799ea8108c38bcb-4c59e9a913c480a3-01",
		"invalid-trace-id4": "00-0x5fe865607da112abd799ea8108c3cb-4c59e9a913c480a3-01",
		"invalid-trace-id5": "00-5FE865607DA112ABD799EA8108C38BCB-4c59e9a913c480a3-01",
		// For parent test, traceID portion must be different each time
		"invalid-parent-id1": "00-11111111111111111111111111111111-Zc59e9a913c480a3-01",
		"invalid-parent-id2": "00-22222222222222222222222222222222-4C59E9A913C480A3-01",
		"invalid-parent-id3": "00-33333333333333333333333333333333-4c59e9aW13c480a3-01",
		"invalid-parent-id4": "00-44444444444444444444444444444444-4c59e9a9-3c480a3-01",
		"invalid-parent-id5": "00-55555555555555555555555555555555-0x59e9a913c480a3-01",
		"invalid-flags-1":    "00-176716bec4d4c0e85df0d39dd70a2b62-c7fe2560276e9ba0-0x",
		"invalid-flags-2":    "00-b97fd2bfb304550fd85c33fdfc821f29-dfca787aa452fcdb-No",
		"not-sampled-flag-1": "00-48ebacb3fe3ebaa5df61f611dda9a094-c1c831f7da1a9309-00",
		"not-sampled-flag-2": "00-d9e4d0f83479f891815e33af16175af8-eaff68618edf4279-f0",
		"not-sampled-flag-3": "00-be8faab0d17fe5424d142a3b356a5d35-d52a68b9f0cf468e-12",
	}
	for slug, traceparent := range slugToParent {
		t.Log("Testing bad traceid. traceparent:", traceparent, "slug:", slug)
		doHTTPGetWithTraceparent(t, instrumentedServiceStdURL+"/"+slug+"?delay=10ms", 200, traceparent)

		var trace jaeger.Trace
		negativeTest := strings.Contains(slug, "flag")
		test.Eventually(t, testTimeout, func(t require.TestingT) {
			if negativeTest {
				// Give time when we're ensuring that a trace is NOT generated
				time.Sleep(testTimeout / 2)
			}
			resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2F" + slug)
			require.NoError(t, err)
			if resp == nil {
				return
			}
			require.Equal(t, http.StatusOK, resp.StatusCode)
			var tq jaeger.TracesQuery
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
			traces := tq.FindBySpan(jaeger.Tag{Key: "http.target", Type: "string", Value: "/" + slug})
			if negativeTest {
				require.Len(t, traces, 0)
			} else {
				require.Len(t, traces, 1)
				trace = traces[0]
			}
		}, test.Interval(100*time.Millisecond))

		if negativeTest {
			continue
		}
		// Check the information of the parent span
		res := trace.FindByOperationName("GET /" + slug)
		require.Len(t, res, 1)
		parent := res[0]
		require.NotEmpty(t, parent.TraceID)
		if strings.Contains(slug, "trace-id") {
			require.NotEqual(t, traceparent[3:35], parent.TraceID)
		} else if strings.Contains(slug, "parent-id") {
			children := trace.ChildrenOf(traceparent[36:52])
			require.Equal(t, len(children), 0)
		}
	}
}

func testGRPCTraces(t *testing.T) {
	testGRPCTracesForServiceName(t, "testserver")
}

func testGRPCTracesForServiceName(t *testing.T, svcName string) {
	require.Error(t, grpcclient.Debug(10*time.Millisecond, true))

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + svcName + "&operation=%2Frouteguide.RouteGuide%2FDebug")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "rpc.method", Type: "string", Value: "/routeguide.RouteGuide/Debug"})
		require.Len(t, traces, 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the parent span
	res := trace.FindByOperationName("/routeguide.RouteGuide/Debug")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	require.NotEmpty(t, parent.SpanID)
	// check duration is at least 10ms (10,000 microseconds)
	assert.Less(t, (10 * time.Millisecond).Microseconds(), parent.Duration)
	// check span attributes
	assert.Truef(t, parent.AllMatches(
		jaeger.Tag{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		jaeger.Tag{Key: "net.host.port", Type: "int64", Value: float64(50051)},
		jaeger.Tag{Key: "rpc.grpc.status_code", Type: "int64", Value: float64(2)},
		jaeger.Tag{Key: "rpc.method", Type: "string", Value: "/routeguide.RouteGuide/Debug"},
		jaeger.Tag{Key: "rpc.system", Type: "string", Value: "grpc"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
		jaeger.Tag{Key: "service.name", Type: "string", Value: svcName},
	), "not all tags matched in %+v", parent.Tags)

	// Check the information of the "in queue" span
	res = trace.FindByOperationName("in queue")
	require.Len(t, res, 1)
	queue := res[0]
	// Check parenthood
	p, ok := trace.ParentOf(&queue)
	require.True(t, ok)
	assert.Equal(t, parent.TraceID, p.TraceID)
	assert.Equal(t, parent.SpanID, p.SpanID)
	// check reasonable start and end times
	assert.GreaterOrEqual(t, queue.StartTime, parent.StartTime)
	assert.LessOrEqual(t,
		queue.StartTime+queue.Duration,
		parent.StartTime+parent.Duration+1) // adding 1 to tolerate inaccuracies from rounding from ns to ms
	// check span attributes
	assert.Truef(t, queue.AllMatches(
		jaeger.Tag{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	), "not all tags matched in %+v", queue.Tags)

	// Check the information of the "processing" span
	res = trace.FindByOperationName("processing")
	require.Len(t, res, 1)
	processing := res[0]
	// Check parenthood
	p, ok = trace.ParentOf(&queue)
	require.True(t, ok)
	assert.Equal(t, parent.TraceID, p.TraceID)
	assert.Equal(t, parent.SpanID, p.SpanID)
	// check reasonable start and end times
	assert.GreaterOrEqual(t, processing.StartTime, queue.StartTime+queue.Duration)
	assert.LessOrEqual(t, processing.StartTime+processing.Duration, parent.StartTime+parent.Duration+1)
	// check span attributes
	assert.Truef(t, queue.AllMatches(
		jaeger.Tag{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	), "not all tags matched in %+v", queue.Tags)

	// check process ID
	require.Contains(t, trace.Processes, parent.ProcessID)
	assert.Equal(t, parent.ProcessID, queue.ProcessID)
	assert.Equal(t, parent.ProcessID, processing.ProcessID)
	process := trace.Processes[parent.ProcessID]
	assert.Equal(t, svcName, process.ServiceName)
	assert.Truef(t, jaeger.AllMatches(process.Tags, []jaeger.Tag{
		{Key: "telemetry.sdk.language", Type: "string", Value: "go"},
		{Key: "service.namespace", Type: "string", Value: "integration-test"},
	}), "not all tags matched in %+v", process.Tags)
}
