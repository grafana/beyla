package filter

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "github.com/grafana/beyla/pkg/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/testutil"
)

const timeout = 5 * time.Second

func TestAttributeFilter(t *testing.T) {
	filterFunc, err := ByAttribute[*ebpf.Record](AttributeFamilyConfig{
		"beyla.ip":          MatchDefinition{Match: "148.*"},
		"k8s.src.namespace": MatchDefinition{NotMatch: "debug"},
	}, ebpf.RecordStringGetters)()
	require.NoError(t, err)

	in := make(chan []*ebpf.Record, 10)
	defer close(in)
	out := make(chan []*ebpf.Record, 10)
	go filterFunc(in, out)

	// records not matching both the ip and src namespace will be dropped
	in <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "debug"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "128.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralar"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "141.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralari"}}},
	}

	// the whole batch will be dropped (won't go to the out channel)
	in <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{BeylaIP: "128.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "141.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralari"}}},
	}

	// no record will be dropped
	in <- []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralar"}}},
	}

	filtered := testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralar"}}},
	}, filtered)

	filtered = testutil.ReadChannel(t, out, timeout)
	assert.Equal(t, []*ebpf.Record{
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.132.1.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "foo"}}},
		{Attrs: ebpf.RecordAttrs{BeylaIP: "148.133.2.1",
			Metadata: map[attr.Name]string{"k8s.src.namespace": "tralar"}}},
	}, filtered)

	select {
	case batch := <-out:
		assert.Failf(t, "not expecting more output batches", "%#v", batch)
	default:
		// ok!!
	}

}

func TestAttributeFilter_VerificationError(t *testing.T) {
	testCases := []AttributeFamilyConfig{
		// non-existing attribute
		{"super-attribute": MatchDefinition{Match: "foo"}},
		// valid attribute without match definition
		{"beyla.ip": MatchDefinition{}},
		// valid attribute with double match definition
		{"beyla.ip": MatchDefinition{Match: "foo", NotMatch: "foo"}},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v", tc), func(t *testing.T) {
			_, err := ByAttribute[*ebpf.Record](tc, ebpf.RecordStringGetters)()
			assert.Error(t, err)
		})
	}
}
