package agent

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/connector"
	attrobi "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/filter"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/export/otel"
	"github.com/grafana/beyla/v2/pkg/export/prom"
	"github.com/grafana/beyla/v2/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/v2/pkg/internal/netolly/flow/transport"
	"github.com/grafana/beyla/v2/pkg/internal/pipe/global"
	prom2 "github.com/grafana/beyla/v2/test/integration/components/prom"
)

const timeout = 5 * time.Second

func TestFilter(t *testing.T) {
	ctx := t.Context()

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
			Attributes: beyla.Attributes{Select: attrobi.Selection{
				attrobi.BeylaNetworkFlow.Section: attrobi.InclusionLists{
					Include: []string{"beyla_ip", "iface.direction", "dst_port", "iface", "src_port", "transport"},
				},
			}},
		},
		interfaceNamer: func(_ int) string { return "fakeiface" },
	}

	ringBuf := make(chan []*ebpf.Record, 10)
	// override eBPF flow fetchers
	newMapTracer = func(_ *Flows, _ *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
		return func(_ context.Context) {}
	}
	newRingBufTracer = func(_ *Flows, out *msg.Queue[[]*ebpf.Record]) swarm.RunFunc {
		return func(_ context.Context) {
			for i := range ringBuf {
				out.Send(i)
			}
		}
	}

	runner, err := flows.buildPipeline(ctx)
	require.NoError(t, err)

	go runner.Start(ctx)

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
				"beyla_ip": "1.2.3.4", "iface_direction": "ingress", "dst_port": "1011", "iface": "fakeiface", "src_port": "789", "transport": "TCP",
			}},
			{Name: "beyla_network_flow_bytes_total", Labels: map[string]string{
				"beyla_ip": "1.2.3.4", "iface_direction": "ingress", "dst_port": "1415", "iface": "fakeiface", "src_port": "1213", "transport": "TCP",
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
