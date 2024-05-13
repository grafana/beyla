package agent

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/mariomac/pipes/pipe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/export/attributes"
	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/grafana/beyla/pkg/internal/export/prom"
	"github.com/grafana/beyla/pkg/internal/filter"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/netolly/flow/transport"
	"github.com/grafana/beyla/pkg/internal/netolly/ifaces"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	prom2 "github.com/grafana/beyla/test/integration/components/prom"
)

const timeout = 5 * time.Second

func TestFilter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	promPort, err := test.FreeTCPPort()
	require.NoError(t, err)

	// Flows pipeline that will discard any network flow not matching the "TCP" transport attribute
	flows := Flows{
		agentIP: net.ParseIP("1.2.3.4"),
		ctxInfo: &global.ContextInfo{
			Prometheus: &connector.PrometheusManager{},
		},
		cfg: &beyla.Config{
			Prometheus: prom.PrometheusConfig{
				Path:     "/metrics",
				Port:     promPort,
				Features: []string{otel.FeatureNetwork},
				TTL:      time.Hour,
			},
			Filters: filter.AttributesConfig{
				Network: map[string]filter.MatchDefinition{"transport": {Match: "TCP"}},
			},
			Attributes: beyla.Attributes{Select: attributes.Selection{
				attributes.BeylaNetworkFlow.Section: attributes.InclusionLists{
					Include: []string{"beyla_ip", "direction", "dst_port", "iface", "src_port", "transport"},
				},
			}},
		},
		interfaces:     fakeInterfacesInformer{},
		interfaceNamer: func(_ int) string { return "fakeiface" },
	}

	pb, err := flows.pipelineBuilder(ctx)
	require.NoError(t, err)

	ringBuf := make(chan []*ebpf.Record, 10)
	// override eBPF flow fetchers
	pipe.AddStart(pb, mapTracer, func(_ chan<- []*ebpf.Record) {})
	pipe.AddStart(pb, ringBufTracer, func(out chan<- []*ebpf.Record) {
		for i := range ringBuf {
			out <- i
		}
	})

	runner, err := pb.Build()
	require.NoError(t, err)

	go runner.Start()

	ringBuf <- []*ebpf.Record{
		fakeRecord(transport.UDP, 123, 456),
		fakeRecord(transport.TCP, 789, 1011),
		fakeRecord(transport.UDP, 333, 444),
	}
	ringBuf <- []*ebpf.Record{
		fakeRecord(transport.TCP, 1213, 1415),
		fakeRecord(transport.UDP, 3333, 8080),
	}

	test.Eventually(t, timeout, func(t require.TestingT) {
		metrics, err := prom2.Scrape(fmt.Sprintf("http://localhost:%d/metrics", promPort))
		require.NoError(t, err)

		// assuming metrics returned alphabetically ordered
		assert.Equal(t, []prom2.ScrapedMetric{
			{Name: "beyla_network_flow_bytes_total", Labels: map[string]string{
				"beyla_ip": "1.2.3.4", "direction": "ingress", "dst_port": "1011", "iface": "fakeiface", "src_port": "789", "transport": "TCP",
			}},
			{Name: "beyla_network_flow_bytes_total", Labels: map[string]string{
				"beyla_ip": "1.2.3.4", "direction": "ingress", "dst_port": "1415", "iface": "fakeiface", "src_port": "1213", "transport": "TCP",
			}},
			// standard prometheus metrics. Leaving them here to simplify test verification
			{Name: "promhttp_metric_handler_errors_total", Labels: map[string]string{"cause": "encoding"}},
			{Name: "promhttp_metric_handler_errors_total", Labels: map[string]string{"cause": "gathering"}},
		}, metrics)

	})
}

func fakeRecord(protocol transport.Protocol, srcPort, dstPort uint16) *ebpf.Record {
	return &ebpf.Record{NetFlowRecordT: ebpf.NetFlowRecordT{
		Id: ebpf.NetFlowId{
			SrcPort: srcPort, DstPort: dstPort, TransportProtocol: uint8(protocol),
		},
	}}
}

type fakeInterfacesInformer struct{}

func (f fakeInterfacesInformer) Subscribe(_ context.Context) (<-chan ifaces.Event, error) {
	return make(<-chan ifaces.Event), nil
}
