//go:build integration

package integration

import (
	"fmt"
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
	testHTTPTracesCommon(t, false, 200)
}

func testHTTPTraces(t *testing.T) {
	testHTTPTracesCommon(t, true, 500)
}

func testHTTPTracesCommon(t *testing.T, doTraceID bool, httpCode int) {
	var traceID string
	var parentID string

	doHTTPGet(t, instrumentedServiceStdURL+"/metrics", 200)
	doHTTPGet(t, instrumentedServiceStdURL+"/metrics", 200)

	slug := "create-trace"
	if doTraceID {
		slug = "create-trace-with-id"
		// Add and check for specific trace ID
		traceID = createTraceID()
		parentID = createParentID()
		traceparent := createTraceparent(traceID, parentID)
		doHTTPGetWithTraceparent(t, fmt.Sprintf("%s/%s?delay=10ms&status=%d", instrumentedServiceStdURL, slug, httpCode), httpCode, traceparent)
	} else {
		doHTTPGet(t, fmt.Sprintf("%s/%s?delay=10ms&status=%d", instrumentedServiceStdURL, slug, httpCode), httpCode)
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
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + slug})
		require.Len(t, traces, 1)
		trace = traces[0]
		require.Len(t, trace.Spans, 3) // parent - in queue - processing
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
	sd := parent.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(httpCode)},
		jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + slug},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8080)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/" + slug},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())

	if httpCode >= 500 {
		sd := parent.Diff(
			jaeger.Tag{Key: "otel.status_code", Type: "string", Value: "ERROR"},
		)
		assert.Empty(t, sd, sd.String())
	}

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
	sd = queue.Diff(
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// Check the information of the "processing" span
	res = trace.FindByOperationName("processing")
	require.Len(t, res, 1)
	processing := res[0]
	// Check parenthood
	p, ok = trace.ParentOf(&processing)
	require.True(t, ok)
	assert.Equal(t, parent.TraceID, p.TraceID)
	assert.Equal(t, parent.SpanID, p.SpanID)
	// check reasonable start and end times
	assert.GreaterOrEqual(t, processing.StartTime, queue.StartTime+queue.Duration)
	assert.LessOrEqual(t,
		processing.StartTime+processing.Duration,
		parent.StartTime+parent.Duration+1)
	sd = queue.Diff(
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// check process ID
	require.Contains(t, trace.Processes, parent.ProcessID)
	assert.Equal(t, parent.ProcessID, queue.ProcessID)
	assert.Equal(t, parent.ProcessID, processing.ProcessID)
	process := trace.Processes[parent.ProcessID]
	assert.Equal(t, "testserver", process.ServiceName)

	serviceInstance, ok := jaeger.FindIn(process.Tags, "service.instance.id")
	require.Truef(t, ok, "service.instance.id not found in tags: %v", process.Tags)
	assert.Regexp(t, `^beyla-\d+$`, serviceInstance.Value)

	jaeger.Diff([]jaeger.Tag{
		{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		{Key: "telemetry.sdk.language", Type: "string", Value: "go"},
		{Key: "telemetry.sdk.name", Type: "string", Value: "beyla"},
		{Key: "service.namespace", Type: "string", Value: "integration-test"},
		serviceInstance,
	}, process.Tags)
	assert.Empty(t, sd, sd.String())

	// Check that /metrics is missing from Jaeger at the same time
	resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fmetrics")
	require.NoError(t, err)
	if resp == nil {
		return
	}
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var tq jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
	traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/metrics"})
	require.Len(t, traces, 0)
}

func testGRPCTraces(t *testing.T) {
	testGRPCTracesForServiceName(t, "testserver")
}

func testGRPCTracesForServiceName(t *testing.T, svcName string) {
	require.Error(t, grpcclient.Debug(10*time.Millisecond, true)) // this call doesn't add anything, the Go SDK will generate traceID and contextID

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
		require.Len(t, trace.Spans, 3) // parent - in queue - processing
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
	sd := parent.Diff(
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(5051)},
		jaeger.Tag{Key: "rpc.grpc.status_code", Type: "int64", Value: float64(2)},
		jaeger.Tag{Key: "rpc.method", Type: "string", Value: "/routeguide.RouteGuide/Debug"},
		jaeger.Tag{Key: "rpc.system", Type: "string", Value: "grpc"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())

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
	sd = queue.Diff(
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// Check the information of the "processing" span
	res = trace.FindByOperationName("processing")
	require.Len(t, res, 1)
	processing := res[0]
	// Check parenthood
	p, ok = trace.ParentOf(&queue)
	require.True(t, ok)
	assert.Equal(t, parent.TraceID, p.TraceID)
	require.False(t, strings.HasSuffix(parent.TraceID, "0000000000000000")) // the Debug call doesn't add any traceparent to the request header, the traceID is auto-generated won't look like this
	assert.Equal(t, parent.SpanID, p.SpanID)
	// check reasonable start and end times
	assert.GreaterOrEqual(t, processing.StartTime, queue.StartTime+queue.Duration)
	assert.LessOrEqual(t, processing.StartTime+processing.Duration, parent.StartTime+parent.Duration+1)
	// check span attributes
	sd = queue.Diff(
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// check process ID
	require.Contains(t, trace.Processes, parent.ProcessID)
	assert.Equal(t, parent.ProcessID, queue.ProcessID)
	assert.Equal(t, parent.ProcessID, processing.ProcessID)
	process := trace.Processes[parent.ProcessID]
	assert.Equal(t, svcName, process.ServiceName)

	serviceInstance, ok := jaeger.FindIn(process.Tags, "service.instance.id")
	require.Truef(t, ok, "service.instance.id not found in tags: %v", process.Tags)
	assert.Regexp(t, `^beyla-\d+$`, serviceInstance.Value)

	jaeger.Diff([]jaeger.Tag{
		{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		{Key: "telemetry.sdk.language", Type: "string", Value: "go"},
		{Key: "service.namespace", Type: "string", Value: "integration-test"},
		serviceInstance,
	}, process.Tags)
	assert.Empty(t, sd, sd.String())

	require.NoError(t, grpcclient.List()) // this call adds traceparent manually to the headers, simulates existing traceparent

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=" + svcName + "&operation=%2Frouteguide.RouteGuide%2FListFeatures")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "rpc.method", Type: "string", Value: "/routeguide.RouteGuide/ListFeatures"})
		require.Len(t, traces, 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the parent span
	res = trace.FindByOperationName("/routeguide.RouteGuide/ListFeatures")
	require.Len(t, res, 1)
	parent = res[0]
	require.NotEmpty(t, parent.TraceID)
	require.NotEmpty(t, parent.SpanID)

	/*
	 The code for grpc Ping() generates spans like these:
	 00-000000000000038b0000000000000000-000000000000038b-01

	 The traceID and spanID increase by one in tandem and it loops forever.
	 We check that the traceID has that 16 character 0 suffix and then we
	 use the first 16 characters for looking up by Parent span.

	 Finding a traceID like the custom pattern means that our traceparent
	 extraction in eBPF works.
	*/
	require.NotEmpty(t, parent.TraceID)
	require.True(t, strings.HasSuffix(parent.TraceID, "0000000000000000"))

	pparent := parent.TraceID[:16]
	childOfPID := trace.ChildrenOf(pparent)
	require.Len(t, childOfPID, 1)
	childSpan := childOfPID[0]
	require.Equal(t, childSpan.TraceID, parent.TraceID)
	require.Equal(t, childSpan.SpanID, parent.SpanID)
}

func testGRPCKProbeTraces(t *testing.T) {
	svcName := "testserver"
	require.Error(t, grpcclient.Debug(10*time.Millisecond, true)) // this call doesn't add anything, the Go SDK will generate traceID and contextID

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
		require.Len(t, trace.Spans, 1) // single span for kprobes, we don't track goroutines
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
	sd := parent.Diff(
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(5051)},
		jaeger.Tag{Key: "rpc.grpc.status_code", Type: "int64", Value: float64(2)},
		jaeger.Tag{Key: "rpc.method", Type: "string", Value: "/routeguide.RouteGuide/Debug"},
		jaeger.Tag{Key: "rpc.system", Type: "string", Value: "grpc"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())
}

func testHTTPTracesKProbes(t *testing.T) {
	var traceID string
	var parentID string

	// Add and check for specific trace ID
	traceID = createTraceID()
	parentID = createParentID()
	traceparent := createTraceparent(traceID, parentID)
	doHTTPGetWithTraceparent(t, "http://localhost:3031/bye", 200, traceparent)

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=node&operation=GET%20%2Fbye")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/bye"})
		require.Len(t, traces, 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the parent span
	res := trace.FindByOperationName("GET /bye")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	if kprobeTraces {
		require.Equal(t, traceID, parent.TraceID)
		// Validate that "parent" is a CHILD_OF the traceparent's "parent-id"
		childOfPID := trace.ChildrenOf(parentID)
		require.Len(t, childOfPID, 1)
	}
	require.NotEmpty(t, parent.SpanID)
	// check duration is at least 2us
	assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
	// check span attributes
	sd := parent.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
		jaeger.Tag{Key: "url.path", Type: "string", Value: "/bye"},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(3030)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/bye"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())

	process := trace.Processes[parent.ProcessID]
	assert.Equal(t, "node", process.ServiceName)

	serviceInstance, ok := jaeger.FindIn(process.Tags, "service.instance.id")
	require.Truef(t, ok, "service.instance.id not found in tags: %v", process.Tags)
	assert.Regexp(t, `^beyla-\d+$`, serviceInstance.Value)

	jaeger.Diff([]jaeger.Tag{
		{Key: "otel.library.name", Type: "string", Value: "github.com/grafana/beyla"},
		{Key: "telemetry.sdk.language", Type: "string", Value: "nodejs"},
		{Key: "telemetry.sdk.name", Type: "string", Value: "beyla"},
		{Key: "service.namespace", Type: "string", Value: "integration-test"},
		serviceInstance,
	}, process.Tags)
	assert.Empty(t, sd, sd.String())
}

func testHTTPTracesNestedCalls(t *testing.T, contextPropagation bool) {
	var traceID string
	var parentID string

	waitForTestComponents(t, "http://localhost:8082")

	// Add and check for specific trace ID
	traceID = createTraceID()
	parentID = createParentID()
	traceparent := createTraceparent(traceID, parentID)
	doHTTPGetWithTraceparent(t, "http://localhost:8082/echo", 203, traceparent)
	// Do some requests to make sure we see all events
	for i := 0; i < 10; i++ {
		doHTTPGet(t, "http://localhost:8082/metrics", 200)
	}

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2Fecho")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/echo"})
		require.Len(t, traces, 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the parent span
	res := trace.FindByOperationName("GET /echo")
	require.Len(t, res, 1)
	server := res[0]
	require.NotEmpty(t, server.TraceID)
	require.Equal(t, traceID, server.TraceID)
	// Validate that "server" is a CHILD_OF the traceparent's "parent-id"
	childOfPID := trace.ChildrenOf(parentID)
	require.Len(t, childOfPID, 1)
	require.NotEmpty(t, server.SpanID)

	// check span attributes
	sd := server.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(203)},
		jaeger.Tag{Key: "url.path", Type: "string", Value: "/echo"},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8082)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/echo"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())

	numNested := 1

	if contextPropagation {
		numNested = 2
	}

	// Check the information of the "in queue" span
	res = trace.FindByOperationName("in queue")
	require.Equal(t, len(res), numNested)

	var queue *jaeger.Span

	for i := range res {
		r := &res[i]
		// Check parenthood
		p, ok := trace.ParentOf(r)

		if ok {
			if p.TraceID == server.TraceID && p.SpanID == server.SpanID {
				queue = r
				break
			}
		}
	}
	require.NotNil(t, queue)
	// check span attributes
	sd = queue.Diff(
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// Check the information of the "processing" span
	res = trace.FindByOperationName("processing")
	require.Equal(t, len(res), numNested)

	var processing *jaeger.Span

	for i := range res {
		r := &res[i]
		// Check parenthood
		p, ok := trace.ParentOf(r)

		if ok {
			if p.TraceID == server.TraceID && p.SpanID == server.SpanID {
				processing = r
				break
			}
		}
	}

	require.NotNil(t, processing)
	sd = queue.Diff(
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// Check the information of the "processing" span
	res = trace.FindByOperationName("GET")
	require.Len(t, res, 1)
	client := res[0]
	// Check parenthood
	p, ok := trace.ParentOf(&client)
	require.True(t, ok)
	assert.Equal(t, processing.TraceID, p.TraceID)
	assert.Equal(t, processing.SpanID, p.SpanID)
	sd = client.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(203)},
		jaeger.Tag{Key: "url.full", Type: "string", Value: "/echoBack"},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8080)}, // client call is to 8080
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"},
	)
	assert.Empty(t, sd, sd.String())
}

func testHTTPTracesNestedClient(t *testing.T) {
	testHTTPTracesNestedCalls(t, false)
}

func testHTTPTracesNestedClientWithContextPropagation(t *testing.T) {
	testHTTPTracesNestedCalls(t, true)
}

//nolint:cyclop
func testHTTP2GRPCTracesNestedCalls(t *testing.T, contextPropagation bool) {
	var traceID string
	var parentID string

	waitForTestComponents(t, "http://localhost:8080")

	// Add and check for specific trace ID
	traceID = createTraceID()
	parentID = createParentID()
	traceparent := createTraceparent(traceID, parentID)
	doHTTPGetWithTraceparent(t, "http://localhost:8080/echoCall", 204, traceparent)
	// Do some requests to make sure we see all events
	for i := 0; i < 10; i++ {
		doHTTPGet(t, "http://localhost:8080/metrics", 200)
	}

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=testserver&operation=GET%20%2FechoCall")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/echoCall"})
		require.Len(t, traces, 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the parent span
	res := trace.FindByOperationName("GET /echoCall")
	require.Len(t, res, 1)
	server := res[0]
	require.NotEmpty(t, server.TraceID)
	require.Equal(t, traceID, server.TraceID)
	// Validate that "server" is a CHILD_OF the traceparent's "parent-id"
	childOfPID := trace.ChildrenOf(parentID)
	require.Len(t, childOfPID, 1)
	require.NotEmpty(t, server.SpanID)

	// check span attributes
	sd := server.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(204)},
		jaeger.Tag{Key: "url.path", Type: "string", Value: "/echoCall"},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8080)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/echoCall"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())

	numNested := 1

	if contextPropagation {
		numNested = 2
	}

	// Check the information of the "in queue" span
	res = trace.FindByOperationName("in queue")
	require.Equal(t, len(res), numNested)

	var queue *jaeger.Span

	for i := range res {
		r := &res[i]
		// Check parenthood
		p, ok := trace.ParentOf(r)

		if ok {
			if p.TraceID == server.TraceID && p.SpanID == server.SpanID {
				queue = r
				break
			}
		}
	}
	require.NotNil(t, queue)
	// check span attributes
	sd = queue.Diff(
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// Check the information of the "processing" span
	res = trace.FindByOperationName("processing")
	require.Equal(t, len(res), numNested)

	var processing *jaeger.Span

	for i := range res {
		r := &res[i]
		// Check parenthood
		p, ok := trace.ParentOf(r)

		if ok {
			if p.TraceID == server.TraceID && p.SpanID == server.SpanID {
				processing = r
				break
			}
		}
	}

	require.NotNil(t, processing)
	sd = queue.Diff(
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "internal"},
	)
	assert.Empty(t, sd, sd.String())

	// Check the information of the "processing" span
	res = trace.FindByOperationName("/routeguide.RouteGuide/GetFeature")
	require.Len(t, res, numNested)
	for index := range res {
		grpc := res[index]
		if contextPropagation {
			assert.Equal(t, processing.TraceID, grpc.TraceID)
		}
		isClient := false

		for _, tag := range grpc.Tags {
			if tag.Key == "span.kind" && tag.Value == "client" {
				isClient = true
			}
		}

		if isClient {
			p, ok := trace.ParentOf(&grpc)
			require.True(t, ok)
			assert.Equal(t, processing.TraceID, p.TraceID)
			assert.Equal(t, processing.SpanID, p.SpanID)
		}

		sd = grpc.Diff(
			jaeger.Tag{Key: "rpc.method", Type: "string", Value: "/routeguide.RouteGuide/GetFeature"},
			jaeger.Tag{Key: "rpc.grpc.status_code", Type: "int64", Value: float64(0)},
		)
		assert.Empty(t, sd, sd.String())
	}
}

func testHTTP2GRPCTracesNestedCallsNoPropagation(t *testing.T) {
	testHTTP2GRPCTracesNestedCalls(t, false)
}

func testHTTP2GRPCTracesNestedCallsWithContextPropagation(t *testing.T) {
	testHTTP2GRPCTracesNestedCalls(t, true)
}

func testNestedHTTPTracesKProbes(t *testing.T) {
	var traceID string

	waitForTestComponents(t, "http://localhost:3031")                 // nodejs
	waitForTestComponents(t, "http://localhost:8080")                 // go
	waitForTestComponents(t, "http://localhost:8183")                 // python
	waitForRubyTestComponents(t, "http://localhost:3041")             // ruby
	waitForTestComponentsSub(t, "http://localhost:8086", "/greeting") // java
	waitForTestComponents(t, "http://localhost:8091")                 // rust

	// Add and check for specific trace ID
	// Run couple of requests to make sure we flush out any transactions that might be
	// stuck because of our tracking of full request times
	for i := 0; i < 10; i++ {
		doHTTPGet(t, "http://localhost:8091/dist", 200)
	}

	// rust   -> java     -> nodejs   -> go            -> python      -> rails
	// /dist2 -> /jtrace2 -> /traceme -> /gotracemetoo -> /tracemetoo -> /users

	// Get the first 5 traces
	var multipleTraces []jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=rust-service&operation=GET%20%2Fdist")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/dist"})
		require.LessOrEqual(t, 5, len(traces))
		multipleTraces = traces
	}, test.Interval(500*time.Millisecond))

	// Ensure all 5 traces have proper full chain
	for _, trace := range multipleTraces {
		// Check the information of the rust parent span
		res := trace.FindByOperationName("GET /dist")
		require.Len(t, res, 1)
		parent := res[0]
		require.NotEmpty(t, parent.TraceID)
		traceID = parent.TraceID
		require.NotEmpty(t, parent.SpanID)
		// check duration is at least 2us
		assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
		// check span attributes
		sd := parent.Diff(
			jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
			jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
			jaeger.Tag{Key: "url.path", Type: "string", Value: "/dist"},
			jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8090)},
			jaeger.Tag{Key: "http.route", Type: "string", Value: "/dist"},
			jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
		)
		assert.Empty(t, sd, sd.String())

		// Check the information of the java parent span
		res = trace.FindByOperationName("GET /jtrace")
		require.Len(t, res, 1)
		parent = res[0]
		require.NotEmpty(t, parent.TraceID)
		require.Equal(t, traceID, parent.TraceID)
		require.NotEmpty(t, parent.SpanID)
		// check duration is at least 2us
		assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
		// check span attributes
		sd = parent.Diff(
			jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
			jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
			jaeger.Tag{Key: "url.path", Type: "string", Value: "/jtrace"},
			jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8085)},
			jaeger.Tag{Key: "http.route", Type: "string", Value: "/jtrace"},
			jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
		)
		assert.Empty(t, sd, sd.String())

		// Check the information of the nodejs parent span
		res = trace.FindByOperationName("GET /traceme")
		require.Len(t, res, 1)
		parent = res[0]
		require.NotEmpty(t, parent.TraceID)
		require.Equal(t, traceID, parent.TraceID)
		require.NotEmpty(t, parent.SpanID)
		// check duration is at least 2us
		assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
		// check span attributes
		sd = parent.Diff(
			jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
			jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
			jaeger.Tag{Key: "url.path", Type: "string", Value: "/traceme"},
			jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(3030)},
			jaeger.Tag{Key: "http.route", Type: "string", Value: "/traceme"},
			jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
		)
		assert.Empty(t, sd, sd.String())

		// Check the information of the go parent span
		res = trace.FindByOperationName("GET /gotracemetoo")
		require.Len(t, res, 1)
		parent = res[0]
		require.NotEmpty(t, parent.TraceID)
		traceID = parent.TraceID // we reset the traceID here
		require.NotEmpty(t, parent.SpanID)
		// check duration is at least 2us
		assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
		// check span attributes
		sd = parent.Diff(
			jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
			jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
			jaeger.Tag{Key: "url.path", Type: "string", Value: "/gotracemetoo"},
			jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8080)},
			jaeger.Tag{Key: "http.route", Type: "string", Value: "/gotracemetoo"},
			jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
		)
		assert.Empty(t, sd, sd.String())

		// Check the information of the python parent span
		res = trace.FindByOperationName("GET /tracemetoo")
		require.Len(t, res, 1)
		parent = res[0]
		require.NotEmpty(t, parent.TraceID)
		require.Equal(t, traceID, parent.TraceID)
		require.NotEmpty(t, parent.SpanID)
		// check duration is at least 2us
		assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
		// check span attributes
		sd = parent.Diff(
			jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
			jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
			jaeger.Tag{Key: "url.path", Type: "string", Value: "/tracemetoo"},
			jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8083)},
			jaeger.Tag{Key: "http.route", Type: "string", Value: "/tracemetoo"},
			jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
		)
		assert.Empty(t, sd, sd.String())

		// Check the information of the rails parent span
		res = trace.FindByOperationName("GET /users")
		require.Len(t, res, 1)
		parent = res[0]
		require.NotEmpty(t, parent.TraceID)
		require.Equal(t, traceID, parent.TraceID)
		require.NotEmpty(t, parent.SpanID)
		// check duration is at least 2us
		assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
		// check span attributes
		sd = parent.Diff(
			jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
			jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(403)}, // something config missing in rails, but 403 is OK :)
			jaeger.Tag{Key: "url.path", Type: "string", Value: "/users"},
			jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(3040)},
			jaeger.Tag{Key: "http.route", Type: "string", Value: "/users"},
			jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
		)
		assert.Empty(t, sd, sd.String())
	}
}

func testNestedHTTPSTracesKProbes(t *testing.T) {
	var traceID string

	waitForTestComponents(t, "https://localhost:8381")
	waitForRubyTestComponents(t, "https://localhost:3044")

	// Add and check for specific trace ID
	doHTTPGet(t, "https://localhost:8381/tracemetoo", 200)

	var trace jaeger.Trace
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		resp, err := http.Get(jaegerQueryURL + "?service=python-service-ssl&operation=GET%20%2Ftracemetoo")
		require.NoError(t, err)
		if resp == nil {
			return
		}
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var tq jaeger.TracesQuery
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&tq))
		traces := tq.FindBySpan(jaeger.Tag{Key: "url.path", Type: "string", Value: "/tracemetoo"})
		require.Len(t, traces, 1)
		trace = traces[0]
	}, test.Interval(100*time.Millisecond))

	// Check the information of the python parent span
	res := trace.FindByOperationName("GET /tracemetoo")
	require.Len(t, res, 1)
	parent := res[0]
	require.NotEmpty(t, parent.TraceID)
	traceID = parent.TraceID
	require.NotEmpty(t, parent.SpanID)
	// check duration is at least 2us
	assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
	// check span attributes
	sd := parent.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(200)},
		jaeger.Tag{Key: "url.path", Type: "string", Value: "/tracemetoo"},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(8380)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/tracemetoo"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())

	// Check the information of the rails parent span
	res = trace.FindByOperationName("GET /users")
	require.Len(t, res, 1)
	parent = res[0]
	require.NotEmpty(t, parent.TraceID)
	require.Equal(t, traceID, parent.TraceID)
	require.NotEmpty(t, parent.SpanID)
	// check duration is at least 2us
	assert.Less(t, (2 * time.Microsecond).Microseconds(), parent.Duration)
	// check span attributes
	sd = parent.Diff(
		jaeger.Tag{Key: "http.request.method", Type: "string", Value: "GET"},
		jaeger.Tag{Key: "http.response.status_code", Type: "int64", Value: float64(403)}, // something config missing in rails, but 403 is OK :)
		jaeger.Tag{Key: "url.path", Type: "string", Value: "/users"},
		jaeger.Tag{Key: "server.port", Type: "int64", Value: float64(3043)},
		jaeger.Tag{Key: "http.route", Type: "string", Value: "/users"},
		jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
	)
	assert.Empty(t, sd, sd.String())
}
