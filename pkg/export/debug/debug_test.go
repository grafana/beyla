package debug

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
)

func TestTracePrinterValidEnabled(t *testing.T) {
	type testData struct {
		printer TracePrinter
		valid   bool
		enabled bool
	}

	printers := []testData{
		{"disabled", true, false},
		{"counter", true, true},
		{"text", true, true},
		{"json", true, true},
		{"json_indent", true, true},
		{"invalid", false, false},
		{"", false, false},
	}

	for i := range printers {
		p := &printers[i]
		assert.Equal(t, p.printer.Valid(), p.valid)
		assert.Equal(t, p.printer.Enabled(), p.enabled)
	}
}

func traceFuncHelper(t *testing.T, tracePrinter TracePrinter) string {
	fakeSpan := request.Span{
		Service:        svc.Attrs{UID: svc.UID{Name: "bar", Namespace: "foo"}, SDKLanguage: svc.InstrumentableGolang},
		Type:           request.EventTypeHTTP,
		Method:         "method",
		Path:           "path",
		Route:          "route",
		Peer:           "peer",
		PeerPort:       1234,
		Host:           "host",
		HostPort:       5678,
		Status:         200,
		ContentLength:  1024,
		ResponseLength: 2048,
		RequestStart:   10000,
		Start:          15000,
		End:            35000,
		TraceID:        trace2.TraceID{0x1, 0x2, 0x3},
		SpanID:         trace2.SpanID{0x1, 0x2, 0x3},
		ParentSpanID:   trace2.SpanID{0x1, 0x2, 0x4},
		Flags:          1,
		PeerName:       "peername",
		HostName:       "hostname",
		OtherNamespace: "otherns",
		Statement:      "statement",
	}

	fakeSpan.SetIgnoreMetrics()

	// redirect the TracePrinter function stdout to a pipe so that we can
	// capture and return its output
	r, w, err := os.Pipe()
	require.NoError(t, err)

	stdout := os.Stdout
	os.Stdout = w

	spanCh := msg.NewQueue[[]request.Span]()

	f := resolvePrinterFunc(tracePrinter, spanCh)
	go func() {
		f(t.Context())
		w.Close()
	}()

	spanCh.Send([]request.Span{fakeSpan})
	spanCh.Close()

	funcOutput, err := io.ReadAll(r)
	r.Close()

	require.NoError(t, err)

	os.Stdout = stdout

	return string(funcOutput)
}

func TestTracePrinterResolve_PrinterText(t *testing.T) {
	expected := "(25µs[20µs]) HTTP 200 method path [peer as peername.otherns:1234]->" +
		"[host as hostname.foo:5678] contentLen:1024B responseLen:2048B svc=[foo/bar go]" +
		" traceparent=[00-01020300000000000000000000000000-0102030000000000[0102040000000000]-01]\n"

	actual := traceFuncHelper(t, TracePrinterText)
	assert.True(t, strings.HasSuffix(actual, expected))
}

func TestTracePrinterResolve_PrinterCounter(t *testing.T) {
	expected := "Processed 1 requests\n"
	actual := traceFuncHelper(t, TracePrinterCounter)
	assert.Equal(t, expected, actual)
}

func TestTracePrinterResolve_PrinterJSON(t *testing.T) {
	// test as separate chunks to exclude timestamps (start, handlerStart, end)

	prefix := `[{"type":"HTTP","ignoreSpan":"Metrics","peer":"peer","peerPort":"1234",` +
		`"host":"host","hostPort":"5678","traceID":"01020300000000000000000000000000",` +
		`"spanID":"0102030000000000","parentSpanID":"0102040000000000","flags":"1",` +
		`"peerName":"peername","hostName":"hostname","kind":"SPAN_KIND_SERVER","`

	suffix := `duration":"25µs","durationUSec":"25","handlerDuration":"20µs",` +
		`"handlerDurationUSec":"20","attributes":{"clientAddr":"peername",` +
		`"contentLen":"1024","method":"method","responseLen":"2048","route":"route",` +
		`"serverAddr":"hostname","serverPort":"5678","status":"200","url":"path"}}]` + "\n"

	actual := traceFuncHelper(t, TracePrinterJSON)
	assert.True(t, strings.HasPrefix(actual, prefix))
	assert.True(t, strings.HasSuffix(actual, suffix))
}

func TestTracePrinterResolve_PrinterJSONIndent(t *testing.T) {
	// test as separate chunks to exclude timestamps (start, handlerStart, end)

	prefix := `[
 {
  "type": "HTTP",
  "ignoreSpan": "Metrics",
  "peer": "peer",
  "peerPort": "1234",
  "host": "host",
  "hostPort": "5678",
  "traceID": "01020300000000000000000000000000",
  "spanID": "0102030000000000",
  "parentSpanID": "0102040000000000",
  "flags": "1",
  "peerName": "peername",
  "hostName": "hostname",
  "kind": "SPAN_KIND_SERVER",`

	suffix := `"duration": "25µs",
  "durationUSec": "25",
  "handlerDuration": "20µs",
  "handlerDurationUSec": "20",
  "attributes": {
   "clientAddr": "peername",
   "contentLen": "1024",
   "method": "method",
   "responseLen": "2048",
   "route": "route",
   "serverAddr": "hostname",
   "serverPort": "5678",
   "status": "200",
   "url": "path"
  }
 }
]
`

	actual := traceFuncHelper(t, TracePrinterJSONIndent)
	assert.True(t, strings.HasPrefix(actual, prefix))
	assert.True(t, strings.HasSuffix(actual, suffix))
}
