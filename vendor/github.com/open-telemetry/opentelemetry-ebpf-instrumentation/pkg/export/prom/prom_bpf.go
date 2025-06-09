package prom

import (
	"context"
	"encoding"
	"log/slog"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/connector"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/pipe/global"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/swarm"
)

// BPFCollector implements prometheus.Collector for collecting metrics about currently loaded eBPF programs.
type BPFCollector struct {
	cfg         *PrometheusConfig
	promConnect *connector.PrometheusManager
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
	ctxInfo *global.ContextInfo,
	cfg *PrometheusConfig,
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !bpfCollectorEnabled(cfg) {
			return swarm.EmptyRunFunc()
		}
		collector := newBPFCollector(ctxInfo, cfg)
		return collector.reportMetrics, nil
	}
}

func bpfCollectorEnabled(cfg *PrometheusConfig) bool {
	return cfg.EndpointEnabled() && cfg.EBPFEnabled()
}

func newBPFCollector(ctxInfo *global.ContextInfo, cfg *PrometheusConfig) *BPFCollector {
	c := &BPFCollector{
		cfg:         cfg,
		log:         slog.With("component", "prom.BPFCollector"),
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

func (bc *BPFCollector) reportMetrics(ctx context.Context) {
	go bc.promConnect.StartHTTP(ctx)
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
	bc.enableBPFStatsRuntime()

	for id := ebpf.ProgramID(0); ; {
		nextID, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			break
		}
		id = nextID

		program, err := ebpf.NewProgramFromID(id)
		if err != nil {
			bc.log.Error("failed to load program", "ID", id, "error", err)
			continue
		}
		defer program.Close()

		info, err := program.Info()
		if err != nil {
			bc.log.Error("failed to get program info", "ID", id, "error", err)
			continue
		}

		switch info.Type {
		case ebpf.Kprobe, ebpf.SocketFilter, ebpf.SchedCLS, ebpf.SkMsg, ebpf.SockOps:
		// Supported program types
		default:
			continue // Skip unsupported program types
		}

		name := getFuncName(info, id, bc.log)

		runtime, _ := info.Runtime()
		runCount, _ := info.RunCount()
		idStr := strconv.FormatUint(uint64(id), 10)

		// Get the previous stats
		probe, ok := bc.progs[id]
		if !ok {
			probe = &BPFProgram{
				runTime:      runtime,
				runCount:     runCount,
				prevRunTime:  0,
				prevRunCount: 0,
			}
			bc.progs[id] = probe
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
			name,
		)
	}
}

func getFuncName(info *ebpf.ProgramInfo, id ebpf.ProgramID, log *slog.Logger) string {
	funcInfos, err := info.FuncInfos()
	if err != nil {
		log.Error("failed to get program func infos", "ID", id, "error", err)
		return info.Name
	}

	for _, funcOffset := range funcInfos {
		if f := funcOffset.Func; f != nil {
			return f.Name
		}
	}
	return info.Name
}

func (bc *BPFCollector) collectMapMetrics(ch chan<- prometheus.Metric) {
	for id := ebpf.MapID(0); ; {
		nextID, err := ebpf.MapGetNextID(id)
		if err != nil {
			break
		}
		id = nextID

		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			bc.log.Error("failed to load map", "ID", id, "error", err)
			continue
		}
		defer m.Close()

		info, err := m.Info()
		if err != nil {
			bc.log.Error("failed to get map info", "ID", id, "error", err)
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
			ch <- prometheus.MustNewConstMetric(
				bc.mapSizeDesc,
				prometheus.CounterValue,
				float64(count),
				strconv.FormatUint(uint64(id), 10),
				info.Name,
				info.Type.String(),
				strconv.FormatUint(uint64(info.MaxEntries), 10),
			)
		}
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
type discardEncoding struct{}

func (de *discardEncoding) UnmarshalBinary(_ []byte) error {
	return nil
}

// sliceDiscardEncoding implements encoding.BinaryMarshaler for eBPF per-cpu map values such that everything is discarded.
type sliceDiscardEncoding []discardEncoding

func (sde *sliceDiscardEncoding) UnmarshalBinary(_ []byte) error {
	return nil
}
