// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"context"
	"encoding"
	"log/slog"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// BPFCollector implements prometheus.Collector for collecting metrics about currently loaded eBPF programs.
type BPFCollector struct {
	promCfg         *PrometheusConfig
	internalMetrics imetrics.Reporter
	promConnect     *connector.PrometheusManager
	ctxInfo         *global.ContextInfo
	log             *slog.Logger

	probeLatencyDesc *prometheus.Desc
	mapSizeDesc      *prometheus.Desc
	progs            map[ebpf.ProgramID]*BPFProgram
}

type BPFProgram struct {
	runTime      time.Duration
	runCount     uint64
	prevRunTime  time.Duration
	prevRunCount uint64
	buckets      map[float64]uint64
}

type ProbeMetrics struct {
	probeType string
	probeName string
	probeID   string
	latency   float64
	count     uint64
	program   *BPFProgram
}

type BpfMapMetrics struct {
	mapType    string
	mapName    string
	mapID      string
	maxEntries int
	entries    uint64
}

func BPFMetrics(
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !bpfCollectorEnabled(cfg, ctxInfo.Metrics) {
			return swarm.EmptyRunFunc()
		}
		collector := newBPFCollector(ctxInfo, cfg)
		return collector.start, nil
	}
}

func internalMetricsOTELEnabled(internalMetrics imetrics.Reporter) bool {
	_, ok := internalMetrics.(*otel.InternalMetricsReporter)
	return ok
}

func promMetricsEnabled(cfg *PrometheusConfig) bool {
	return cfg.EndpointEnabled() && cfg.EBPFEnabled()
}

func bpfCollectorEnabled(cfg *PrometheusConfig, internalMetrics imetrics.Reporter) bool {
	return promMetricsEnabled(cfg) || internalMetricsOTELEnabled(internalMetrics)
}

func newBPFCollector(ctxInfo *global.ContextInfo, cfg *PrometheusConfig) *BPFCollector {
	c := &BPFCollector{
		promCfg:         cfg,
		internalMetrics: ctxInfo.Metrics,
		log:             slog.With("component", "prom.BPFCollector"),
		ctxInfo:         ctxInfo,
		promConnect:     ctxInfo.Prometheus,
		progs:           make(map[ebpf.ProgramID]*BPFProgram),
		probeLatencyDesc: prometheus.NewDesc(
			prometheus.BuildFQName("bpf", "probe", "latency_seconds"),
			"Latency of the probe in seconds",
			[]string{"probe_id", "probe_type", "probe_name"},
			nil,
		),
		mapSizeDesc: prometheus.NewDesc(
			prometheus.BuildFQName("bpf", "map", "entries_total"),
			"Number of entries in the map",
			[]string{"map_id", "map_name", "map_type", "max_entries"},
			nil,
		),
	}
	if promMetricsEnabled(cfg) {
		// Register the collector
		c.promConnect.Register(cfg.Port, cfg.Path, c)
	}
	return c
}

func (bc *BPFCollector) start(ctx context.Context) {
	if promMetricsEnabled(bc.promCfg) {
		bc.reportMetrics(ctx)
	} else {
		go bc.collectInternalMetrics(ctx)
	}
}

func (bc *BPFCollector) reportMetrics(ctx context.Context) {
	go bc.promConnect.StartHTTP(ctx)
}

func (bc *BPFCollector) collectInternalMetrics(ctx context.Context) {
	ticker := time.NewTicker(bc.internalMetrics.BpfInternalMetricsScrapeInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			probeMetrics := bc.getProbeMetrics()
			for _, metric := range probeMetrics {
				// TODO: this is not the most efficient way to report histogram metrics,
				// but with otel metrics we don't have a way to report histograms based on count and latency, like filling buckets with prometheus.
				// options are either to create counter with an le label, or just report count and sum of latencies, and drop the histogram.
				for range metric.count {
					bc.ctxInfo.Metrics.BpfProbeLatency(metric.probeID, metric.probeType, metric.probeName, metric.latency)
				}
			}

			mapMetrics := bc.getMapMetrics()
			for _, metric := range mapMetrics {
				bc.ctxInfo.Metrics.BpfMapEntries(metric.mapID, metric.mapName, metric.mapType, int(metric.entries))
				bc.ctxInfo.Metrics.BpfMapMaxEntries(metric.mapID, metric.mapName, metric.mapType, metric.maxEntries)
			}
		}
	}
}

func (bc *BPFCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- bc.probeLatencyDesc
}

func (bc *BPFCollector) Collect(ch chan<- prometheus.Metric) {
	bc.log.Debug("Collecting eBPF metrics")
	probeMetrics := bc.getProbeMetrics()
	for _, metric := range probeMetrics {
		metric.program.updateBuckets(metric.latency, metric.count)

		// Create the histogram metric
		ch <- prometheus.MustNewConstHistogram(
			bc.probeLatencyDesc,
			metric.program.runCount,
			metric.program.runTime.Seconds(),
			metric.program.buckets,
			metric.probeID,
			metric.probeType,
			metric.probeName,
		)
	}
	mapMetrics := bc.getMapMetrics()
	for _, metric := range mapMetrics {
		ch <- prometheus.MustNewConstMetric(
			bc.mapSizeDesc,
			prometheus.CounterValue,
			float64(metric.entries),
			metric.mapID,
			metric.mapName,
			metric.mapType,
			strconv.FormatUint(uint64(metric.maxEntries), 10),
		)
	}
}

func (bc *BPFCollector) getProbeMetrics() []ProbeMetrics {
	bc.enableBPFStatsRuntime()

	probeMetrics := make([]ProbeMetrics, 0)

	for id := ebpf.ProgramID(0); ; {
		nextID, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			break
		}
		id = nextID

		program, err := ebpf.NewProgramFromID(id)
		if err != nil {
			bc.log.Debug("failed to load program", "ID", id, "error", err)
			continue
		}
		defer program.Close()

		info, err := program.Info()
		if err != nil {
			bc.log.Debug("failed to get program info", "ID", id, "error", err)
			continue
		}

		switch info.Type {
		case ebpf.Kprobe, ebpf.SocketFilter, ebpf.SchedCLS, ebpf.SkMsg, ebpf.SockOps:
		// Supported program types
		default:
			continue // Skip unsupported program types
		}

		name := getFuncName(info, id, bc.log)

		stats, err := program.Stats()
		if err != nil {
			bc.log.Debug("failed to get program stats", "ID", id, "error", err)
			continue
		}

		idStr := strconv.FormatUint(uint64(id), 10)

		// Get the previous stats
		probe, ok := bc.progs[id]
		if !ok {
			probe = &BPFProgram{
				runTime:      stats.Runtime,
				runCount:     stats.RunCount,
				prevRunTime:  0,
				prevRunCount: 0,
			}
			bc.progs[id] = probe
		} else {
			probe.prevRunTime = probe.runTime
			probe.prevRunCount = probe.runCount
			probe.runTime = stats.Runtime
			probe.runCount = stats.RunCount
		}
		latency, count := probe.calculateStats()
		probeMetrics = append(probeMetrics, ProbeMetrics{
			probeID:   idStr,
			probeType: info.Type.String(),
			probeName: name,
			latency:   latency,
			count:     count,
			program:   probe,
		})
	}
	return probeMetrics
}

func getFuncName(info *ebpf.ProgramInfo, id ebpf.ProgramID, log *slog.Logger) string {
	funcInfos, err := info.FuncInfos()
	if err != nil {
		log.Debug("failed to get program func infos", "ID", id, "error", err)
		return info.Name
	}

	for _, funcOffset := range funcInfos {
		if f := funcOffset.Func; f != nil {
			return f.Name
		}
	}
	return info.Name
}

func (bc *BPFCollector) getMapMetrics() []BpfMapMetrics {
	mapMetrics := make([]BpfMapMetrics, 0)
	for id := ebpf.MapID(0); ; {
		nextID, err := ebpf.MapGetNextID(id)
		if err != nil {
			break
		}
		id = nextID

		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			bc.log.Debug("failed to load map", "ID", id, "error", err)
			continue
		}
		defer m.Close()

		info, err := m.Info()
		if err != nil {
			bc.log.Debug("failed to get map info", "ID", id, "error", err)
			continue
		}

		// Only collect maps that are LRUHash
		if info.Type != ebpf.LRUHash {
			continue
		}

		var count uint64
		throwawayKey := discardEncoding{}
		throwawayValues := make(sliceDiscardEncoding, 0)
		iter := m.Iterate()
		for iter.Next(&throwawayKey, &throwawayValues) {
			count++
		}
		if err := iter.Err(); err == nil {
			mapID := strconv.FormatUint(uint64(id), 10)
			mapType := info.Type.String()
			mapMetrics = append(mapMetrics, BpfMapMetrics{
				mapType:    mapType,
				mapName:    info.Name,
				mapID:      mapID,
				maxEntries: int(info.MaxEntries),
				entries:    count,
			})
		}
	}
	return mapMetrics
}

func (bp *BPFProgram) calculateStats() (float64, uint64) {
	// Calculate the difference in runtime and run count
	deltaTime := bp.runTime - bp.prevRunTime
	deltaCount := bp.runCount - bp.prevRunCount

	if deltaCount <= 0 {
		return 0.0, 0
	}
	return deltaTime.Seconds() / float64(deltaCount), deltaCount
}

// updateBuckets update the histogram buckets for the given data based on previous data.
func (bp *BPFProgram) updateBuckets(latency float64, count uint64) {
	// Update the buckets
	if bp.buckets == nil {
		bp.buckets = make(map[float64]uint64)
	}
	for _, bucket := range imetrics.BpfLatenciesBuckets {
		if count > 0 && latency <= bucket {
			bp.buckets[bucket] += count
			break
		}
	}
}

// Assert that discardEncoding implements the correct interfaces for map iterators.
var (
	_ encoding.BinaryUnmarshaler = (*discardEncoding)(nil)
	_ encoding.BinaryUnmarshaler = (*sliceDiscardEncoding)(nil)
)

// discardEncoding implements encoding.BinaryMarshaler for eBPF map values such that everything is discarded.
type discardEncoding struct{}

func (de *discardEncoding) UnmarshalBinary(_ []byte) error {
	return nil
}

// sliceDiscardEncoding implements encoding.BinaryMarshaler for eBPF per-cpu map values such that everything is discarded.
type sliceDiscardEncoding []discardEncoding

func (sde *sliceDiscardEncoding) UnmarshalBinary(_ []byte) error {
	return nil
}
