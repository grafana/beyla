// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"context"
	"encoding"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
)

// BPFCollector implements prometheus.Collector for collecting metrics about currently loaded eBPF programs.
type BPFCollector struct {
	promCfg         *PrometheusConfig
	commonCfg       *perapp.GlobalMetricsConfig
	internalMetrics imetrics.Reporter
	promConnect     *connector.PrometheusManager
	ctxInfo         *global.ContextInfo
	log             *slog.Logger

	probeLatencyDesc *prometheus.Desc
	mapSizeDesc      *prometheus.Desc
	mapMaxSizeDesc   *prometheus.Desc
	progs            map[ebpf.ProgramID]*BPFProgram
	programCache     map[ebpf.ProgramID]*cachedProgram
	mapCache         map[ebpf.MapID]*cachedMap
	probeMetrics     func() []ProbeMetrics
	mapMetrics       func() []BpfMapMetrics
	closeBPFStats    func()
	mu               sync.Mutex
	closed           bool
}

type cachedProgram struct {
	supported bool
	probeType string
	probeName string
	probeID   string
}

type cachedMap struct {
	supported  bool
	mapType    string
	mapName    string
	mapID      string
	maxEntries int
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
	mpCfg *perapp.GlobalMetricsConfig,
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		promEnabled := promMetricsEnabled(cfg, mpCfg)
		internalEnabled := internalMetricsEnabled(ctxInfo.Metrics)
		if !promEnabled && !internalEnabled {
			return swarm.EmptyRunFunc()
		}

		runFns := make([]swarm.RunFunc, 0, 2)
		if promEnabled {
			collector := newBPFCollectorFn(ctxInfo, cfg, mpCfg)
			collector.cleanupOnContext(ctx)
			runFns = append(runFns, collector.startPrometheus)
		}
		if internalEnabled {
			collector := newInternalBPFCollectorFn(ctxInfo, cfg, mpCfg)
			collector.cleanupOnContext(ctx)
			runFns = append(runFns, collector.startInternalMetrics)
		}

		return func(ctx context.Context) {
			for _, run := range runFns {
				run(ctx)
			}
		}, nil
	}
}

var (
	newBPFCollectorFn         = newBPFCollector
	newInternalBPFCollectorFn = newInternalBPFCollector
)

func internalMetricsEnabled(internalMetrics imetrics.Reporter) bool {
	if internalMetrics == nil || imetrics.IsBuiltinNoopReporter(internalMetrics) {
		return false
	}

	return internalMetrics.BpfInternalMetricsScrapeInterval() > 0
}

func promMetricsEnabled(cfg *PrometheusConfig, mpCfg *perapp.GlobalMetricsConfig) bool {
	return cfg.EndpointEnabled() && mpCfg.Features.BPF()
}

func bpfCollectorEnabled(cfg *PrometheusConfig, mpCfg *perapp.GlobalMetricsConfig, internalMetrics imetrics.Reporter) bool {
	return promMetricsEnabled(cfg, mpCfg) || internalMetricsEnabled(internalMetrics)
}

func newBPFCollector(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.GlobalMetricsConfig) *BPFCollector {
	return newCollector(ctxInfo, cfg, mpCfg, true)
}

func newInternalBPFCollector(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.GlobalMetricsConfig) *BPFCollector {
	return newCollector(ctxInfo, cfg, mpCfg, false)
}

func newCollector(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.GlobalMetricsConfig, registerProm bool) *BPFCollector {
	c := &BPFCollector{
		promCfg:         cfg,
		commonCfg:       mpCfg,
		internalMetrics: ctxInfo.Metrics,
		log:             slog.With("component", "prom.BPFCollector"),
		ctxInfo:         ctxInfo,
		promConnect:     ctxInfo.Prometheus,
		progs:           make(map[ebpf.ProgramID]*BPFProgram),
		programCache:    make(map[ebpf.ProgramID]*cachedProgram),
		mapCache:        make(map[ebpf.MapID]*cachedMap),
		probeLatencyDesc: prometheus.NewDesc(
			prometheus.BuildFQName("bpf", "probe", "latency_seconds"),
			"Latency of the probe in seconds",
			[]string{attr.BpfProbeID.Prom(), attr.BpfProbeType.Prom(), attr.BpfProbeName.Prom()},
			nil,
		),
		mapSizeDesc: prometheus.NewDesc(
			prometheus.BuildFQName("bpf", "map", "entries"),
			"Number of entries in the map",
			[]string{attr.BpfMapID.Prom(), attr.BpfMapName.Prom(), attr.BpfMapType.Prom()},
			nil,
		),
		mapMaxSizeDesc: prometheus.NewDesc(
			prometheus.BuildFQName("bpf", "map", "max_entries"),
			"Maximum number of entries the map can hold",
			[]string{attr.BpfMapID.Prom(), attr.BpfMapName.Prom(), attr.BpfMapType.Prom()},
			nil,
		),
	}
	c.probeMetrics = c.getProbeMetrics
	c.mapMetrics = c.getMapMetrics
	c.closeBPFStats = c.enableBPFStatsRuntime()
	if registerProm && promMetricsEnabled(cfg, mpCfg) {
		// Register the collector
		c.promConnect.Register(cfg.Port, cfg.Path, c)
	}
	return c
}

func (bc *BPFCollector) startPrometheus(ctx context.Context) {
	bc.cleanupOnContext(ctx)
	bc.reportMetrics(ctx)
}

func (bc *BPFCollector) startInternalMetrics(ctx context.Context) {
	if !internalMetricsEnabled(bc.internalMetrics) {
		return
	}
	bc.cleanupOnContext(ctx)
	go bc.collectInternalMetrics(ctx)
}

func (bc *BPFCollector) cleanupOnContext(ctx context.Context) {
	done := ctx.Done()
	if done == nil {
		return
	}

	go func() {
		<-done
		bc.close()
	}()
}

func (bc *BPFCollector) close() {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.closed {
		return
	}
	bc.closed = true
	if bc.closeBPFStats != nil {
		bc.closeBPFStats()
		bc.closeBPFStats = nil
	}
	clear(bc.programCache)
	clear(bc.mapCache)
	clear(bc.progs)
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
			probeMetrics, mapMetrics := bc.collectMetrics()
			for _, metric := range probeMetrics {
				if metric.count == 0 {
					continue
				}

				metric.program.updateBuckets(metric.latency, metric.count)

				bc.ctxInfo.Metrics.BpfProbeStats(
					metric.probeID,
					metric.probeType,
					metric.probeName,
					metric.count,
					metric.latency*float64(metric.count),
					metric.program.buckets,
				)
			}

			for _, metric := range mapMetrics {
				bc.ctxInfo.Metrics.BpfMapEntries(metric.mapID, metric.mapName, metric.mapType, int(metric.entries))
				bc.ctxInfo.Metrics.BpfMapMaxEntries(metric.mapID, metric.mapName, metric.mapType, metric.maxEntries)
			}
		}
	}
}

func (bc *BPFCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- bc.probeLatencyDesc
	ch <- bc.mapSizeDesc
	ch <- bc.mapMaxSizeDesc
}

func (bc *BPFCollector) Collect(ch chan<- prometheus.Metric) {
	bc.log.Debug("Collecting eBPF metrics")
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.closed {
		return
	}

	probeMetrics := bc.probeMetrics()
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
	mapMetrics := bc.mapMetrics()
	for _, metric := range mapMetrics {
		ch <- prometheus.MustNewConstMetric(
			bc.mapSizeDesc,
			prometheus.GaugeValue,
			float64(metric.entries),
			metric.mapID,
			metric.mapName,
			metric.mapType,
		)
		ch <- prometheus.MustNewConstMetric(
			bc.mapMaxSizeDesc,
			prometheus.GaugeValue,
			float64(metric.maxEntries),
			metric.mapID,
			metric.mapName,
			metric.mapType,
		)
	}
}

func (bc *BPFCollector) collectMetrics() ([]ProbeMetrics, []BpfMapMetrics) {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if bc.closed {
		return nil, nil
	}

	return bc.probeMetrics(), bc.mapMetrics()
}

func (bc *BPFCollector) getProbeMetrics() []ProbeMetrics {
	probeMetrics := make([]ProbeMetrics, 0, len(bc.programCache))
	seen := make(map[ebpf.ProgramID]struct{}, len(bc.programCache))
	completeWalk := false

	for id := ebpf.ProgramID(0); ; {
		nextID, err := ebpf.ProgramGetNextID(id)
		if err != nil {
			completeWalk = errors.Is(err, os.ErrNotExist)
			break
		}
		id = nextID
		seen[id] = struct{}{}

		cached, ok := bc.programCache[id]
		if ok && !cached.supported {
			continue
		}

		program, err := ebpf.NewProgramFromID(id)
		if err != nil {
			bc.log.Debug("failed to load program", "ID", id, "error", err)
			continue
		}

		if !ok {
			cached = bc.cacheProgram(id, program)
		}
		if cached == nil || !cached.supported {
			bc.closeProgram(id, program)
			continue
		}

		stats, err := program.Stats()
		bc.closeProgram(id, program)
		if err != nil {
			bc.log.Debug("failed to get program stats", "ID", id, "error", err)
			continue
		}

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
			probeID:   cached.probeID,
			probeType: cached.probeType,
			probeName: cached.probeName,
			latency:   latency,
			count:     count,
			program:   probe,
		})
	}

	if completeWalk {
		bc.evictMissingPrograms(seen)
	}

	return probeMetrics
}

func (bc *BPFCollector) cacheProgram(id ebpf.ProgramID, program *ebpf.Program) *cachedProgram {
	info, err := program.Info()
	if err != nil {
		bc.log.Debug("failed to get program info", "ID", id, "error", err)
		return nil
	}

	if !supportedProgramType(info.Type) {
		cached := &cachedProgram{}
		bc.programCache[id] = cached
		return cached
	}

	cached := &cachedProgram{
		supported: true,
		probeType: info.Type.String(),
		probeName: getFuncName(info, id, bc.log),
		probeID:   strconv.FormatUint(uint64(id), 10),
	}
	bc.programCache[id] = cached
	return cached
}

func supportedProgramType(programType ebpf.ProgramType) bool {
	switch programType {
	case ebpf.Kprobe, ebpf.SocketFilter, ebpf.SchedCLS, ebpf.SkMsg, ebpf.SockOps:
		return true
	default:
		return false
	}
}

func (bc *BPFCollector) evictMissingPrograms(seen map[ebpf.ProgramID]struct{}) {
	for id := range bc.programCache {
		if _, ok := seen[id]; ok {
			continue
		}
		delete(bc.programCache, id)
		delete(bc.progs, id)
	}
}

func (bc *BPFCollector) closeProgram(id ebpf.ProgramID, program *ebpf.Program) {
	if err := program.Close(); err != nil {
		bc.log.Debug("failed to close program", "ID", id, "error", err)
	}
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
	mapMetrics := make([]BpfMapMetrics, 0, len(bc.mapCache))
	seen := make(map[ebpf.MapID]struct{}, len(bc.mapCache))
	completeWalk := false

	for id := ebpf.MapID(0); ; {
		nextID, err := ebpf.MapGetNextID(id)
		if err != nil {
			completeWalk = errors.Is(err, os.ErrNotExist)
			break
		}
		id = nextID
		seen[id] = struct{}{}

		cached, ok := bc.mapCache[id]
		if !ok {
			cached = bc.cacheMap(id)
		}
		if cached == nil || !cached.supported {
			continue
		}

		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			bc.log.Debug("failed to load map for entry iteration", "ID", id, "error", err)
			continue
		}
		count, err := countMapEntries(m)
		if closeErr := m.Close(); closeErr != nil {
			bc.log.Debug("failed to close map", "ID", id, "error", closeErr)
		}
		if err != nil {
			continue
		}

		mapMetrics = append(mapMetrics, BpfMapMetrics{
			mapType:    cached.mapType,
			mapName:    cached.mapName,
			mapID:      cached.mapID,
			maxEntries: cached.maxEntries,
			entries:    count,
		})
	}

	if completeWalk {
		for id := range bc.mapCache {
			if _, ok := seen[id]; !ok {
				delete(bc.mapCache, id)
			}
		}
	}

	return mapMetrics
}

func (bc *BPFCollector) cacheMap(id ebpf.MapID) *cachedMap {
	m, err := ebpf.NewMapFromID(id)
	if err != nil {
		bc.log.Debug("failed to load map", "ID", id, "error", err)
		return nil
	}

	info, infoErr := m.Info()
	if closeErr := m.Close(); closeErr != nil {
		bc.log.Debug("failed to close map", "ID", id, "error", closeErr)
	}
	if infoErr != nil {
		bc.log.Debug("failed to get map info", "ID", id, "error", infoErr)
		return nil
	}

	cached := &cachedMap{
		supported:  info.Type == ebpf.LRUHash,
		mapType:    info.Type.String(),
		mapName:    info.Name,
		mapID:      strconv.FormatUint(uint64(id), 10),
		maxEntries: int(info.MaxEntries),
	}
	bc.mapCache[id] = cached
	return cached
}

func countMapEntries(m *ebpf.Map) (uint64, error) {
	var count uint64
	throwawayKey := discardEncoding{}
	throwawayValues := make(sliceDiscardEncoding, 0)
	iter := m.Iterate()
	for iter.Next(&throwawayKey, &throwawayValues) {
		count++
	}
	return count, iter.Err()
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
