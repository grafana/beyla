//go:build integration

package gpumetrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v3/pkg/internal/infraolly/gpu"
)

// Exercise real sysfs discovery, sampling and Prometheus HTTP exposition together.
func TestGPUIntegration(t *testing.T) {
	root := t.TempDir()
	dev := filepath.Join(root, "class", "drm", "card0", "device")
	require.NoError(t, os.MkdirAll(dev, 0o755))
	for name, value := range map[string]string{
		"vendor": "0x1002", "uevent": "DRIVER=amdgpu\nPCI_ID=1002:744C\nPCI_SLOT_NAME=0000:03:00.0",
		"product_name": "Test GPU", "unique_id": "gpu-test", "gpu_busy_percent": "42",
		"mem_info_vram_total": "1000", "mem_info_vram_used": "250",
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dev, name), []byte(value+"\n"), 0o644))
	}
	source := gpu.NewCollector(gpu.CollectorConfig{SysRoot: root, CacheTTL: time.Nanosecond})
	registry := prometheus.NewRegistry()
	require.NoError(t, registry.Register(newPromCollector(&PromConfig{HostID: "test-host", HostName: "test-node"}, source, newProcesses())))
	server := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	defer server.Close()
	scrape := func() string {
		resp, err := server.Client().Get(server.URL)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return string(body)
	}
	labels := `host_id="test-host",host_name="test-node",hw_gpu_task="general",hw_id="gpu-test",hw_name="Test GPU",hw_vendor="amd"`
	require.Contains(t, scrape(), "hw_gpu_utilization_ratio{"+labels+"} 0.42")
	require.NoError(t, os.WriteFile(filepath.Join(dev, "gpu_busy_percent"), []byte("75\n"), 0o644))
	require.Contains(t, scrape(), "hw_gpu_utilization_ratio{"+labels+"} 0.75")
	require.NoError(t, os.Remove(filepath.Join(dev, "gpu_busy_percent")))
	require.NotContains(t, scrape(), "hw_gpu_utilization_ratio{")
}
