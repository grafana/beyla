package prom

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScrape(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, err := writer.Write([]byte(`#
# HELP beyla_network_flow_bytes_total bytes submitted from a source network endpoint to a destination network endpoint
# TYPE beyla_network_flow_bytes_total counter
beyla_network_flow_bytes_total{beyla_ip="1.2.3.4",dst_port="1011",iface="fakeiface",iface_direction="ingress",src_port="789",transport="TCP"} 123.3
beyla_network_flow_bytes_total{beyla_ip="1.2.3.4",dst_port="1415",iface="fakeiface",iface_direction="ingress",src_port="1213",transport="TCP"} 1
# HELP promhttp_metric_handler_errors_total Total number of internal errors encountered by the promhttp metric handler.
# TYPE promhttp_metric_handler_errors_total counter
promhttp_metric_handler_errors_total{cause="encoding"} 2
promhttp_metric_handler_errors_total{cause="gathering"} 3
			`))
		require.NoError(t, err)
	}))
	defer server.Close()

	scrapedMetrics, err := Scrape(server.URL)
	require.NoError(t, err)
	assert.Equal(t, []ScrapedMetric{
		{Name: "beyla_network_flow_bytes_total", Value: 123.3, Labels: map[string]string{
			"beyla_ip": "1.2.3.4", "iface_direction": "ingress", "dst_port": "1011", "iface": "fakeiface", "src_port": "789", "transport": "TCP",
		}},
		{Name: "beyla_network_flow_bytes_total", Value: 1, Labels: map[string]string{
			"beyla_ip": "1.2.3.4", "iface_direction": "ingress", "dst_port": "1415", "iface": "fakeiface", "src_port": "1213", "transport": "TCP",
		}},
		{Name: "promhttp_metric_handler_errors_total", Value: 2, Labels: map[string]string{"cause": "encoding"}},
		{Name: "promhttp_metric_handler_errors_total", Value: 3, Labels: map[string]string{"cause": "gathering"}},
	}, scrapedMetrics)
}
