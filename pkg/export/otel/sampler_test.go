package otel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/sdk/trace"
)

func TestSamplerImplementation(t *testing.T) {
	type testCase struct {
		in  Sampler
		out trace.Sampler
	}

	for _, tc := range []testCase{{
		// default sampler
		out: trace.ParentBased(trace.AlwaysSample()),
	}, {
		in:  Sampler{Name: "invalid_sampler", Arg: "0.33"},
		out: trace.ParentBased(trace.AlwaysSample()),
	}, {
		in:  Sampler{Name: "always_on"},
		out: trace.AlwaysSample(),
	}, {
		in:  Sampler{Name: "always_off"},
		out: trace.NeverSample(),
	}, {
		in:  Sampler{Name: "traceidratio", Arg: "0.33"},
		out: trace.TraceIDRatioBased(0.33),
	}, {
		// wrong argument: using default sampler
		in:  Sampler{Name: "traceidratio", Arg: "fofofofoof"},
		out: trace.ParentBased(trace.AlwaysSample()),
	}, {
		in:  Sampler{Name: "parentbased_always_off", Arg: "0.33"},
		out: trace.ParentBased(trace.NeverSample()),
	}, {
		in:  Sampler{Name: "parentbased_always_on", Arg: "0.33"},
		out: trace.ParentBased(trace.AlwaysSample()),
	}, {
		in:  Sampler{Name: "parentbased_traceidratio", Arg: "0.3"},
		out: trace.ParentBased(trace.TraceIDRatioBased(0.3)),
	}, {
		in:  Sampler{Name: "parentbased_traceidratio", Arg: "wrong argument"},
		out: trace.ParentBased(trace.AlwaysSample()),
	}} {
		t.Run(tc.in.Name+"/"+tc.in.Arg, func(t *testing.T) {
			assert.Equal(t, tc.out, tc.in.Implementation())
		})
	}
}
