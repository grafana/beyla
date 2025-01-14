package prom

import (
	"context"
	"encoding"
	"log/slog"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/mariomac/pipes/pipe"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"

	"github.com/grafana/beyla/pkg/internal/connector"
	"github.com/grafana/beyla/pkg/internal/pipe/global"
	"github.com/grafana/beyla/pkg/internal/request"
)

// BPFCollector implements prometheus.Collector for collecting metrics about currently loaded eBPF programs.
type BPFCollector struct {
	cfg         *PrometheusConfig
	promConnect *connector.PrometheusManager
	bgCtx       context.Context
	ctxInfo     *global.ContextInfo
	log         *slog.Logger

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

var bucketKeysSeconds = []float64{
	0.0000001,
	0.0000005,
	0.000001,
	0.000002,
	0.000005,
	0.00001,
	0.00002,
	0.00005,
	0.0001,
	0.0002,
	0.0005,
	0.001,
	0.002,
	0.005,
}

func BPFMetrics(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
) pipe.FinalProvider[[]request.Span] {
	return func() (pipe.FinalFunc[[]request.Span], error) {
		if !cfg.EndpointEnabled() && !cfg.EBPFEnabled() {
			return pipe.IgnoreFinal[[]request.Span](), nil
		}
		collector := newBPFCollector(ctx, ctxInfo, cfg)
		return collector.reportMetrics, nil
	}
}

func newBPFCollector(ctx context.Context, ctxInfo *global.ContextInfo, cfg *PrometheusConfig) *BPFCollector {
	c := &BPFCollector{
		cfg:         cfg,
		log:         slog.With("component", "prom.BPFCollector"),
		bgCtx:       ctx,
		ctxInfo:     ctxInfo,
		promConnect: ctxInfo.Prometheus,
		progs:       make(map[ebpf.ProgramID]*BPFProgram),
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
	// Register the collector
	c.promConnect.Register(cfg.Port, cfg.Path, c)
	return c
}

func (bc *BPFCollector) reportMetrics(_ <-chan []request.Span) {
	go bc.promConnect.StartHTTP(bc.bgCtx)
}

func (bc *BPFCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- bc.probeLatencyDesc
}

func (bc *BPFCollector) Collect(ch chan<- prometheus.Metric) {
	bc.log.Debug("Collecting eBPF metrics")
	bc.collectProbesMetrics(ch)
	bc.collectMapMetrics(ch)
}

func (bc *BPFCollector) collectProbesMetrics(ch chan<- prometheus.Metric) {
	_, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
	if err != nil {
		bc.log.Error("failed to enable runtime stats", "error", err)
	}

	// Iterate over all eBPF programs
	ids, err := ebpf.ProgramGetNextID(0)
	if err != nil {
		bc.log.Error("failed to get first program ID", "ID", ids, "error", err)
	}

	for ids != 0 {
		// Get the program from the ID
		program, err := ebpf.NewProgramFromID(ids)
		if err != nil {
			bc.log.Error("failed to load program", "ID", ids, "error", err)
			continue
		}
		defer program.Close()

		// Get program info
		info, err := program.Info()
		if err != nil {
			bc.log.Error("failed to get program info", "ID", ids, "error", err)
			continue
		}

		runtime, _ := info.Runtime()
		runCount, _ := info.RunCount()
		idStr := strconv.FormatUint(uint64(ids), 10)

		// Get the previous stats
		probe, ok := bc.progs[ids]
		if !ok {
			probe = &BPFProgram{
				runTime:      runtime,
				runCount:     runCount,
				prevRunTime:  0,
				prevRunCount: 0,
			}
			bc.progs[ids] = probe
		} else {
			probe.prevRunTime = probe.runTime
			probe.prevRunCount = probe.runCount
			probe.runTime = runtime
			probe.runCount = runCount
		}
		probe.updateBuckets()

		// Create the histogram metric
		ch <- prometheus.MustNewConstHistogram(
			bc.probeLatencyDesc,
			runCount,
			runtime.Seconds(),
			probe.buckets,
			idStr,
			info.Type.String(),
			info.Name,
		)

		// Get the next program ID
		ids, _ = ebpf.ProgramGetNextID(ids)
	}
}

func (bc *BPFCollector) collectMapMetrics(ch chan<- prometheus.Metric) {
	// Iterate over all eBPF maps
	ids, err := ebpf.MapGetNextID(0)
	if err != nil {
		bc.log.Error("failed to get first map ID", "ID", ids, "error", err)
	}

	for ids != 0 {
		// Get the map from the ID
		m, err := ebpf.NewMapFromID(ids)
		if err != nil {
			bc.log.Error("failed to load map", "ID", ids, "error", err)
			continue
		}
		defer m.Close()

		// Get map info
		info, err := m.Info()
		if err != nil {
			bc.log.Error("failed to get map info", "ID", ids, "error", err)
			continue
		}

		// This snippet is copied from digitalocean-labs/ebpf_exporter
		// https://github.com/digitalocean-labs/ebpf_exporter/blob/main/collectors/map.go
		var count uint64
		throwawayKey := discardEncoding{}
		throwawayValues := make(sliceDiscardEncoding, 0)
		iter := m.Iterate()
		for iter.Next(&throwawayKey, &throwawayValues) {
			count++
		}
		if err := iter.Err(); err == nil {
			// Create the map metric
			ch <- prometheus.MustNewConstMetric(
				bc.mapSizeDesc,
				prometheus.CounterValue,
				float64(count),
				strconv.FormatUint(uint64(ids), 10),
				info.Name,
				info.Type.String(),
				strconv.FormatUint(uint64(info.MaxEntries), 10),
			)
		}

		// Get the next map ID
		ids, _ = ebpf.MapGetNextID(ids)
	}
}

// updateBuckets update the histogram buckets for the given data based on previous data.
func (bp *BPFProgram) updateBuckets() {
	// Calculate the difference in runtime and run count
	deltaTime := bp.runTime - bp.prevRunTime
	deltaCount := bp.runCount - bp.prevRunCount

	// Calculate the average latency
	var avgLatency float64
	if deltaCount > 0 {
		avgLatency = deltaTime.Seconds() / float64(deltaCount)
	} else {
		avgLatency = 0
	}

	// Update the buckets
	if bp.buckets == nil {
		bp.buckets = make(map[float64]uint64)
	}
	for _, bucket := range bucketKeysSeconds {
		if deltaCount > 0 && avgLatency <= bucket {
			bp.buckets[bucket] += deltaCount
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
type discardEncoding struct {
}

func (de *discardEncoding) UnmarshalBinary(_ []byte) error {
	return nil
}

// sliceDiscardEncoding implements encoding.BinaryMarshaler for eBPF per-cpu map values such that everything is discarded.
type sliceDiscardEncoding []discardEncoding

func (sde *sliceDiscardEncoding) UnmarshalBinary(_ []byte) error {
	return nil
}
