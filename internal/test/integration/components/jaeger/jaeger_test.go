package jaeger

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This test is still using the old OpenTelemetry semantic convention, but that's fine
// since we only test our Jaeger request parsing functionality.
func TestFind(t *testing.T) {
	traces := Fixture().FindBySpan(
		Tag{Key: "http.method", Type: "string", Value: "GET"},
		Tag{Key: "http.status_code", Type: "int64", Value: float64(200)},
		Tag{Key: "http.target", Type: "string", Value: "/holanena"})
	require.Len(t, traces, 1)
	trace := &traces[0]
	assert.Empty(t, trace.FindByOperationName("hola", ""))
	sp := trace.FindByOperationName("processing", "")
	require.Len(t, sp, 1)
	assert.Equal(t, "processing", sp[0].OperationName)
	parent, ok := trace.ParentOf(&sp[0])
	require.True(t, ok)
	assert.Equal(t, "GET /holanena", parent.OperationName)
	p, ok := trace.ParentOf(&parent)
	require.Falsef(t, ok, "unexpected parent: %+v", p)
	children := trace.ChildrenOf(parent.SpanID)
	assert.Len(t, children, 2)
	assert.Equal(t, "processing", children[0].OperationName)
	assert.Empty(t, trace.ChildrenOf(children[0].SpanID))
	assert.Equal(t, "in queue", children[1].OperationName)
	assert.Empty(t, trace.ChildrenOf(children[1].SpanID))

	traces = Fixture().FindBySpan(
		Tag{Key: "http.method", Type: "string", Value: "GET"},
		Tag{Key: "http.status_code", Type: "int64", Value: float64(200)})
	assert.Len(t, traces, 2)

	traces = Fixture().FindBySpan(
		Tag{Key: "http.method", Type: "string", Value: "POST"},
		Tag{Key: "http.status_code", Type: "int64", Value: float64(200)})
	assert.Empty(t, traces)
}

func Fixture() *TracesQuery {
	var t TracesQuery
	err := json.Unmarshal([]byte(`{"data":[{"traceID":"eae56fbbec9505c102e8aabfc6b5c481","spans":[{"traceID":"eae56fbbec9505c102e8aabfc`+
		`6b5c481","spanID":"89cbc1f60aab3b04","operationName":"in queue","references":[{"refType":"CHILD_OF","traceID":"ea`+
		`e56fbbec9505c102e8aabfc6b5c481","spanID":"1eef766536d58ec8"}],"startTime":1686641491452470,"duration":2845,"tags"`+
		`:[{"key":"otel.library.name","type":"string","value":"github.com/grafana/beyla"},{"key":"span.kind"`+
		`,"type":"string","value":"internal"},{"key":"internal.span.format","type":"string","value":"proto"}],"logs":[],"p`+
		`rocessID":"p1","warnings":null},{"traceID":"eae56fbbec9505c102e8aabfc6b5c481","spanID":"783b655f78525376","operat`+
		`ionName":"processing","references":[{"refType":"CHILD_OF","traceID":"eae56fbbec9505c102e8aabfc6b5c481","spanID":"`+
		`1eef766536d58ec8"}],"startTime":1686641491455316,"duration":476,"tags":[{"key":"otel.library.name","type":"string`+
		`","value":"github.com/grafana/beyla"},{"key":"span.kind","type":"string","value":"internal"},{"key"`+
		`:"internal.span.format","type":"string","value":"proto"}],"logs":[],"processID":"p1","warnings":null},{"traceID":`+
		`"eae56fbbec9505c102e8aabfc6b5c481","spanID":"1eef766536d58ec8","operationName":"GET /holanen","references":[],"st`+
		`artTime":1686641491452470,"duration":3322,"tags":[{"key":"otel.library.name","type":"string","value":"github.com/`+
		`grafana/beyla"},{"key":"http.method","type":"string","value":"GET"},{"key":"http.status_code","type`+
		`":"int64","value":200},{"key":"http.target","type":"string","value":"/holanen"},{"key":"net.sock.peer.addr","type`+
		`":"string","value":"172.18.0.1"},{"key":"net.host.name","type":"string","value":"localhost"},{"key":"net.host.por`+
		`t","type":"int64","value":8080},{"key":"http.request_content_length","type":"int64","value":0},{"key":"http.route`+
		`","type":"string","value":"/holanen"},{"key":"span.kind","type":"string","value":"server"},{"key":"internal.span.`+
		`format","type":"string","value":"proto"}],"logs":[],"processID":"p1","warnings":null}],"processes":{"p1":{"servic`+
		`eName":"testserver","tags":[{"key":"service.namespace","type":"string","value":"integration-test"},{"key":"teleme`+
		`try.sdk.language","type":"string","value":"go"}]}},"warnings":null},{"traceID":"af9ccbccbddc06accc7047dfb0d69ea0"`+
		`,"spans":[{"traceID":"af9ccbccbddc06accc7047dfb0d69ea0","spanID":"0c904394258e390c","operationName":"GET /holanen`+
		`a","references":[],"startTime":1686641494868532,"duration":1108,"tags":[{"key":"otel.library.name","type":"string`+
		`","value":"github.com/grafana/beyla"},{"key":"http.method","type":"string","value":"GET"},{"key":"h`+
		`ttp.status_code","type":"int64","value":200},{"key":"http.target","type":"string","value":"/holanena"},{"key":"ne`+
		`t.sock.peer.addr","type":"string","value":"172.18.0.1"},{"key":"net.host.name","type":"string","value":"localhost`+
		`"},{"key":"net.host.port","type":"int64","value":8080},{"key":"http.request_content_length","type":"int64","value`+
		`":0},{"key":"http.route","type":"string","value":"/holanena"},{"key":"span.kind","type":"string","value":"server"`+
		`},{"key":"internal.span.format","type":"string","value":"proto"}],"logs":[],"processID":"p1","warnings":null},{"t`+
		`raceID":"af9ccbccbddc06accc7047dfb0d69ea0","spanID":"7f7ff70e4c139830","operationName":"processing","references":`+
		`[{"refType":"CHILD_OF","traceID":"af9ccbccbddc06accc7047dfb0d69ea0","spanID":"0c904394258e390c"}],"startTime":168`+
		`6641494869530,"duration":109,"tags":[{"key":"otel.library.name","type":"string","value":"github.com/grafana/ebpf-`+
		`autoinstrument"},{"key":"span.kind","type":"string","value":"internal"},{"key":"internal.span.format","type":"str`+
		`ing","value":"proto"}],"logs":[],"processID":"p1","warnings":null},{"traceID":"af9ccbccbddc06accc7047dfb0d69ea0",`+
		`"spanID":"29b1da78526e9c57","operationName":"in queue","references":[{"refType":"CHILD_OF","traceID":"af9ccbccbdd`+
		`c06accc7047dfb0d69ea0","spanID":"0c904394258e390c"}],"startTime":1686641494868532,"duration":998,"tags":[{"key":"`+
		`otel.library.name","type":"string","value":"github.com/grafana/beyla"},{"key":"span.kind","type":"s`+
		`tring","value":"internal"},{"key":"internal.span.format","type":"string","value":"proto"}],"logs":[],"processID":`+
		`"p1","warnings":null}],"processes":{"p1":{"serviceName":"testserver","tags":[{"key":"service.namespace","type":"s`+
		`tring","value":"integration-test"},{"key":"telemetry.sdk.language","type":"string","value":"go"}]}},"warnings":nu`+
		`ll}],"total":0,"limit":0,"offset":0,"errors":null}`), &t)
	if err != nil {
		panic(err)
	}
	return &t
}

func TestDiff(t *testing.T) {
	expected := []Tag{
		{Key: "foo", Type: "string", Value: 123},
		{Key: "match", Type: "int", Value: 321},
		{Key: "baz", Type: "float", Value: 111},
		{Key: "nf", Type: "float", Value: 321},
	}
	actual := []Tag{
		{Key: "baz", Type: "float", Value: 111},
		{Key: "match", Type: "string", Value: 321},
		{Key: "foo", Type: "string", Value: 321},
	}
	dr := Diff(expected, actual)
	t.Log(dr.String())
	assert.Equal(t, dr, DiffResult{
		{ErrType: ErrTypeNotEqual, Expected: expected[0], Actual: actual[2]},
		{ErrType: ErrTypeNotEqual, Expected: expected[1], Actual: actual[1]},
		{ErrType: ErrTypeMissing, Expected: expected[3]},
	})
}

func TestDiff_Matching(t *testing.T) {
	expected := []Tag{
		{Key: "foo", Type: "string", Value: 123},
		{Key: "match", Type: "int", Value: 321},
		{Key: "baz", Type: "float", Value: 111},
		{Key: "nf", Type: "float", Value: 321},
	}
	actual := []Tag{
		expected[1], expected[3], expected[0], expected[2],
		// any tag in the actual set is ignored if not specified in the "expected" set
		{Key: "triliri", Type: "float", Value: 111},
		{Key: "tralara", Type: "string", Value: 321},
	}
	dr := Diff(expected, actual)
	t.Log(dr.String())
	assert.Emptyf(t, dr, "expected empty but got: %s", dr.String())
}
