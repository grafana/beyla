package debug

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	trace2 "go.opentelemetry.io/otel/trace"

	"github.com/grafana/beyla/pkg/internal/request"
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
		Type:           request.EventTypeHTTP,
		IgnoreSpan:     request.IgnoreMetrics,
		Method:         "method",
		Path:           "path",
		Route:          "route",
		Peer:           "peer",
		PeerPort:       1234,
		Host:           "host",
		HostPort:       5678,
		Status:         200,
		ContentLength:  1024,
		RequestStart:   10000,
		Start:          15000,
		End:            35000,
		TraceID:        trace2.TraceID{0x1, 0x2, 0x3},
		SpanID:         trace2.SpanID{0x1, 0x2, 0x3},
		ParentSpanID:   trace2.SpanID{0x1, 0x2, 0x3},
		Flags:          1,
		PeerName:       "peername",
		HostName:       "hostname",
		OtherNamespace: "otherns",
		Statement:      "statement",
	}

	// redirect the TracePrinter function stdout to a pipe so that we can
	// capture and return its output
	r, w, err := os.Pipe()
	require.NoError(t, err)

	stdout := os.Stdout
	os.Stdout = w

	spanCh := make(chan []request.Span)

	go func() {
		f := resolvePrinterFunc(tracePrinter)
		f(spanCh)
		w.Close()
	}()

	spanCh <- []request.Span{fakeSpan}
	close(spanCh)

	funcOutput, err := io.ReadAll(r)
	r.Close()

	require.NoError(t, err)

	os.Stdout = stdout

	return string(funcOutput)
}

func TestTracePrinterResolve_PrinterText(t *testing.T) {
	expected := "2024-07-20 13:31:54.72013154 (25µs[20µs]) HTTP 200 method path" +
		" [peer as peername:1234]->[host as hostname:5678] size:1024B svc=[ go]" +
		" traceparent=[00-01020300000000000000000000000000-0102030000000000-01]\n"

	actual := traceFuncHelper(t, TracePrinterText)
	assert.Equal(t, expected, actual)
}

func TestTracePrinterResolve_PrinterCounter(t *testing.T) {
	expected := "Processed 1 requests\n"
	actual := traceFuncHelper(t, TracePrinterCounter)
	assert.Equal(t, expected, actual)
}

func TestTracePrinterResolve_PrinterJSON(t *testing.T) {
	expected := `[{"type":"HTTP","ignoreSpan":"Metrics","peer":"peer","peerPort":"1234",` +
		`"host":"host","hostPort":"5678","traceID":"01020300000000000000000000000000",` +
		`"spanID":"0102030000000000","parentSpanID":"0102030000000000","flags":"1",` +
		`"peerName":"peername","hostName":"hostname","kind":"SERVER","start":"1721503914233133",` +
		`"handlerStart":"1721503914233138","end":"1721503914233158","duration":"25µs",` +
		`"durationUSec":"25","handlerDuration":"20µs","handlerDurationUSec":"20","attributes":` +
		`{"clientAddr":"peername","contentLen":"1024","method":"method","route":"route",` +
		`"serverAddr":"hostname","serverPort":"5678","status":"200","url":"path"}}]` + "\n"

	actual := traceFuncHelper(t, TracePrinterJSON)
	assert.Equal(t, expected, actual)
}

func TestTracePrinterResolve_PrinterJSONIndent(t *testing.T) {
	expected := `[
 {
  "type": "HTTP",
  "ignoreSpan": "Metrics",
  "peer": "peer",
  "peerPort": "1234",
  "host": "host",
  "hostPort": "5678",
  "traceID": "01020300000000000000000000000000",
  "spanID": "0102030000000000",
  "parentSpanID": "0102030000000000",
  "flags": "1",
  "peerName": "peername",
  "hostName": "hostname",
  "kind": "SERVER",
  "start": "1721503914233133",
  "handlerStart": "1721503914233138",
  "end": "1721503914233158",
  "duration": "25µs",
  "durationUSec": "25",
  "handlerDuration": "20µs",
  "handlerDurationUSec": "20",
  "attributes": {
   "clientAddr": "peername",
   "contentLen": "1024",
   "method": "method",
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
	assert.Equal(t, expected, actual)
}

func TestTracePrinterResolve_PrinterDisabledInvalid(t *testing.T) {
	assert.Nil(t, resolvePrinterFunc(TracePrinterDisabled))
	assert.Nil(t, resolvePrinterFunc(TracePrinter("")))
	assert.Nil(t, resolvePrinterFunc(TracePrinter("INVALID")))
}
