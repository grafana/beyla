// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/meta"
	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/expire"
	"go.opentelemetry.io/obi/pkg/export/otel/metric"
	instrument "go.opentelemetry.io/obi/pkg/export/otel/metric/api/metric"
	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

func rmlog() *slog.Logger {
	return slog.With("component", "otel.RuntimeMetricsReporter")
}

type RuntimeMetricsReporter struct {
	ctx            context.Context
	cfg            *otelcfg.MetricsConfig
	nodeMeta       meta.NodeMeta
	exporter       sdkmetric.Exporter
	reporters      otelcfg.ReporterPool[*svc.Attrs, *RuntimeMetrics]
	input          <-chan []runtimemetrics.RuntimeMetricSnapshot
	processEvents  <-chan exec.ProcessEvent
	pidTracker     PidServiceTracker
	log            *slog.Logger
	selector       attributes.Selection
	runtimeEnabled runtimemetrics.Enabled
}

type RuntimeMetrics struct {
	ctx                 context.Context
	service             *svc.Attrs
	provider            *metric.MeterProvider
	goHistogramProducer *goRuntimeHistogramProducer

	goMetrics     goRuntimeMetrics
	jvmMetrics    jvmRuntimeMetrics
	nodejsMetrics nodejsRuntimeMetrics
	pythonMetrics pythonRuntimeMetrics
}

type pythonRuntimeMetrics struct {
	collections          instrument.Int64Counter
	collectedObjects     instrument.Int64Counter
	uncollectableObjects instrument.Int64Counter

	values map[app.PID]*pythonRuntimeMetricValues
}

type pythonRuntimeMetricValues struct {
	collections          [runtimemetrics.CPythonGCGenerationCount]pythonRuntimeCounterValue
	collectedObjects     [runtimemetrics.CPythonGCGenerationCount]pythonRuntimeCounterValue
	uncollectableObjects [runtimemetrics.CPythonGCGenerationCount]pythonRuntimeCounterValue
}

type pythonRuntimeCounterValue struct {
	value       uint64
	initialized bool
}

type goRuntimeMetrics struct {
	memoryLimit       instrument.Int64UpDownCounter
	memoryGCGoal      instrument.Int64UpDownCounter
	memoryGCCycles    instrument.Int64Counter
	memoryUsed        instrument.Int64UpDownCounter
	memoryAllocated   instrument.Int64Counter
	memoryAllocations instrument.Int64Counter
	cpuTime           instrument.Float64Counter
	goroutineCount    instrument.Int64UpDownCounter
	processorLimit    instrument.Int64UpDownCounter
	configGOGC        instrument.Int64UpDownCounter

	memoryLimitValue       *int64
	memoryGCGoalValue      *int64
	memoryGCCyclesValue    *uint64
	memoryUsedValues       map[string]int64
	memoryAllocatedValue   *uint64
	memoryAllocationsValue *uint64
	cpuTimeValues          map[string]int64
	goroutineCountValue    *int64
	processorLimitValue    *int64
	configGOGCValue        *int64
}

func ReportRuntimeMetrics(
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	jointMetricsConfig *perapp.GlobalMetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot],
	processEvents *msg.Queue[exec.ProcessEvent],
) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		runtimeEnabled := runtimemetrics.EnabledFeatures(jointMetricsConfig.Features)
		if !cfg.EndpointEnabled() ||
			!runtimeEnabled.Any() ||
			input == nil ||
			processEvents == nil {
			return swarm.EmptyRunFunc()
		}
		otelcfg.SetupInternalOTELSDKLogger(cfg.SDKLogLevel)

		reporter, err := newRuntimeMetricsReporter(
			ctx, ctxInfo, cfg, jointMetricsConfig, selectorCfg, input, processEvents,
		)
		if err != nil {
			return nil, fmt.Errorf("instantiating OTEL runtime metrics reporter: %w", err)
		}

		return reporter.reportMetrics, nil
	}
}

func newRuntimeMetricsReporter(
	ctx context.Context,
	ctxInfo *global.ContextInfo,
	cfg *otelcfg.MetricsConfig,
	jointMetricsConfig *perapp.GlobalMetricsConfig,
	selectorCfg *attributes.SelectorConfig,
	input *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot],
	processEvents *msg.Queue[exec.ProcessEvent],
) (*RuntimeMetricsReporter, error) {
	log := rmlog()

	exporter, err := ctxInfo.OTELMetricsExporter.Instantiate(ctx)
	if err != nil {
		return nil, err
	}

	reporter := &RuntimeMetricsReporter{
		ctx:            ctx,
		cfg:            cfg,
		nodeMeta:       ctxInfo.NodeMeta,
		exporter:       instrumentMetricsExporter(ctxInfo.Metrics, exporter),
		input:          input.Subscribe(msg.SubscriberName("otel.RuntimeMetricsReporter")),
		processEvents:  processEvents.Subscribe(msg.SubscriberName("otel.RuntimeMetricsReporter.ProcessEvents")),
		pidTracker:     NewPidServiceTracker(),
		log:            log,
		selector:       selectorCfg.SelectionCfg,
		runtimeEnabled: runtimemetrics.EnabledFeatures(jointMetricsConfig.Features),
	}

	reporter.reporters, err = otelcfg.NewReporterPool[*svc.Attrs, *RuntimeMetrics](cfg.ReportersCacheLen, cfg.TTL, timeNow,
		func(_ svc.UID, v *RuntimeMetrics) {
			llog := log.With("service", v.service.UID)
			llog.Debug("evicting runtime metrics reporter from cache")

			go func() {
				if err := v.provider.Shutdown(ctx); err != nil {
					llog.Warn("error shutting down evicted runtime metrics provider", "error", err)
				}
			}()
		}, reporter.newMetricSet)
	if err != nil {
		return nil, fmt.Errorf("creating runtime metrics reporters pool: %w", err)
	}

	return reporter, nil
}

func (r *RuntimeMetricsReporter) newMetricsInstance(service *svc.Attrs) RuntimeMetrics {
	var resourceAttributes []attribute.KeyValue
	if service != nil {
		resourceAttributes = append(otelcfg.GetAppResourceAttrs(&r.nodeMeta, service), otelcfg.ResourceAttrsFromEnv(service)...)
		resourceAttributes = otelcfg.FilterResourceAttrs(resourceAttributes, r.selector)
	}
	log := r.log.With("service", service)
	log.Debug("creating new runtime metrics reporter")

	resources := resource.NewWithAttributes(attr.OBISchemaURL, resourceAttributes...)
	goHistogramProducer := newGoRuntimeHistogramProducer(
		r.exporter.Temporality(sdkmetric.InstrumentKindHistogram),
	)
	provider := metric.NewMeterProvider(
		metric.WithResource(resources),
		metric.WithReader(metric.NewPeriodicReader(sharedExporter{r.exporter},
			metric.WithInterval(r.cfg.Interval),
			metric.WithProducer(goHistogramProducer))),
	)

	return RuntimeMetrics{
		ctx:                 r.ctx,
		service:             service,
		provider:            provider,
		goHistogramProducer: goHistogramProducer,
	}
}

func (r *RuntimeMetricsReporter) newMetricSet(service *svc.Attrs) (*RuntimeMetrics, error) {
	metrics := r.newMetricsInstance(service)
	meter := metrics.provider.Meter(reporterName)
	if err := setupRuntimeMeters(&metrics, meter, r.cfg.TTL, r.runtimeEnabled, r.cfg.Buckets); err != nil {
		return nil, err
	}
	return &metrics, nil
}

func setupRuntimeMeters(
	metrics *RuntimeMetrics,
	meter instrument.Meter,
	ttl time.Duration,
	enabled runtimemetrics.Enabled,
	buckets export.Buckets,
) error {
	if !enabled.Runtime {
		return nil
	}
	if err := setupGoRuntimeMeters(&metrics.goMetrics, meter); err != nil {
		return err
	}
	if err := setupJVMRuntimeMeters(metrics.ctx, &metrics.jvmMetrics, meter, ttl); err != nil {
		return err
	}
	if err := setupNodejsRuntimeMeters(metrics.ctx, &metrics.nodejsMetrics, meter, ttl, buckets); err != nil {
		return err
	}
	if err := setupPythonRuntimeMeters(&metrics.pythonMetrics, meter); err != nil {
		return err
	}
	return nil
}

func setupPythonRuntimeMeters(metrics *pythonRuntimeMetrics, meter instrument.Meter) error {
	var err error
	metrics.collections, err = meter.Int64Counter(
		attributes.CPythonGCCollections.OTEL,
		instrument.WithUnit("{collection}"),
		instrument.WithDescription("The number of times a generation was collected since interpreter start."),
	)
	if err != nil {
		return fmt.Errorf("creating CPython GC collections: %w", err)
	}
	metrics.collectedObjects, err = meter.Int64Counter(
		attributes.CPythonGCCollectedObjects.OTEL,
		instrument.WithUnit("{object}"),
		instrument.WithDescription("The total number of objects collected inside a generation since interpreter start."),
	)
	if err != nil {
		return fmt.Errorf("creating CPython GC collected objects: %w", err)
	}
	metrics.uncollectableObjects, err = meter.Int64Counter(
		attributes.CPythonGCUncollectableObjects.OTEL,
		instrument.WithUnit("{object}"),
		instrument.WithDescription("The total number of objects which were found to be uncollectable inside a generation since interpreter start."),
	)
	if err != nil {
		return fmt.Errorf("creating CPython GC uncollectable objects: %w", err)
	}
	return nil
}

func setupGoRuntimeMeters(metrics *goRuntimeMetrics, meter instrument.Meter) error {
	var err error
	metrics.memoryLimit, err = meter.Int64UpDownCounter(attributes.GoRuntimeMemoryLimit.OTEL, instrument.WithUnit(attributes.GoRuntimeMemoryLimit.Unit))
	if err != nil {
		return fmt.Errorf("creating go memory limit: %w", err)
	}
	metrics.memoryGCGoal, err = meter.Int64UpDownCounter(attributes.GoRuntimeMemoryGCGoal.OTEL, instrument.WithUnit(attributes.GoRuntimeMemoryGCGoal.Unit))
	if err != nil {
		return fmt.Errorf("creating go memory gc goal: %w", err)
	}
	metrics.memoryGCCycles, err = meter.Int64Counter(attributes.GoRuntimeMemoryGCCycles.OTEL, instrument.WithUnit(attributes.GoRuntimeMemoryGCCycles.Unit))
	if err != nil {
		return fmt.Errorf("creating go memory gc cycles: %w", err)
	}
	metrics.memoryUsed, err = meter.Int64UpDownCounter(attributes.GoRuntimeMemoryUsed.OTEL, instrument.WithUnit(attributes.GoRuntimeMemoryUsed.Unit))
	if err != nil {
		return fmt.Errorf("creating go memory used: %w", err)
	}
	metrics.memoryAllocated, err = meter.Int64Counter(attributes.GoRuntimeMemoryAllocated.OTEL, instrument.WithUnit(attributes.GoRuntimeMemoryAllocated.Unit))
	if err != nil {
		return fmt.Errorf("creating go memory allocated: %w", err)
	}
	metrics.memoryAllocations, err = meter.Int64Counter(attributes.GoRuntimeMemoryAllocations.OTEL, instrument.WithUnit(attributes.GoRuntimeMemoryAllocations.Unit))
	if err != nil {
		return fmt.Errorf("creating go memory allocations: %w", err)
	}
	metrics.cpuTime, err = meter.Float64Counter(attributes.GoRuntimeCPUTime.OTEL, instrument.WithUnit(attributes.GoRuntimeCPUTime.Unit))
	if err != nil {
		return fmt.Errorf("creating go cpu time: %w", err)
	}
	metrics.goroutineCount, err = meter.Int64UpDownCounter(
		attributes.GoRuntimeGoroutineCount.OTEL,
		instrument.WithUnit(attributes.GoRuntimeGoroutineCount.Unit),
	)
	if err != nil {
		return fmt.Errorf("creating go goroutine count: %w", err)
	}
	metrics.processorLimit, err = meter.Int64UpDownCounter(attributes.GoRuntimeProcessorLimit.OTEL, instrument.WithUnit(attributes.GoRuntimeProcessorLimit.Unit))
	if err != nil {
		return fmt.Errorf("creating go processor limit: %w", err)
	}
	metrics.configGOGC, err = meter.Int64UpDownCounter(attributes.GoRuntimeConfigGOGC.OTEL, instrument.WithUnit(attributes.GoRuntimeConfigGOGC.Unit))
	if err != nil {
		return fmt.Errorf("creating go config gogc: %w", err)
	}

	return nil
}

func (r *RuntimeMetricsReporter) reportMetrics(ctx context.Context) {
	defer r.close()

	for {
		select {
		case <-ctx.Done():
			r.log.Debug("context done, stopping runtime metrics reporting")
			return
		case pe, ok := <-r.processEvents:
			if !ok {
				r.log.Debug("process events channel closed, stopping runtime metrics reporting")
				return
			}
			r.onProcessEvent(&pe)
		case snapshots, ok := <-r.input:
			if !ok {
				r.log.Debug("runtime metrics input channel closed, stopping metrics reporting")
				return
			}
			r.reportRuntimeMetrics(snapshots)
		}
	}
}

func (r *RuntimeMetricsReporter) onProcessEvent(pe *exec.ProcessEvent) {
	if pe.Type == exec.ProcessEventTerminated {
		r.reportRuntimeMetrics(runtimemetrics.PythonRuntimeMetricsFromProcessEvent(*pe))
	}
	service := pe.ServiceFile().ServiceAttrs()
	pid := pe.File.Pid()

	if pe.Type == exec.ProcessEventCreated {
		if trackedUID, exists := r.pidTracker.TracksPID(pid); exists {
			if !trackedUID.Equals(&service.UID) {
				r.pidTracker.ReplaceUID(trackedUID, service.UID)
				r.removeRuntimeReporter(trackedUID)
				return
			}
			if metrics, exists := r.reporters.Lookup(trackedUID); exists &&
				metrics.service != nil && !sameRuntimeMetricService(*metrics.service, service) {
				r.removeRuntimeReporter(trackedUID)
			}
			return
		}
		r.pidTracker.AddPIDWithGeneration(pid, service.UID, pe.File.RuntimeMetricGeneration(pid))
		return
	}

	uid, tracked := r.pidTracker.TracksPID(pid)
	if !tracked {
		return
	}
	if metrics, exists := r.reporters.Lookup(uid); exists {
		if metrics.goHistogramProducer != nil {
			metrics.goHistogramProducer.Delete(pid)
		}
		metrics.jvmMetrics.deleteProcess(pid, pe.File.RuntimeMetricGeneration(pid))
	}
	// Keep final Python counters available until the reporter cache expires them.
	if removed, _ := r.pidTracker.RemovePID(pid); removed && service.SDKLanguage != svc.InstrumentablePython {
		r.removeRuntimeReporter(uid)
	}
}

func (r *RuntimeMetricsReporter) removeRuntimeReporter(uid svc.UID) {
	r.reporters.Remove(uid)
}

func sameRuntimeMetricService(left, right svc.Attrs) bool {
	return left.UID == right.UID &&
		left.HostName == right.HostName &&
		left.ExportModes == right.ExportModes &&
		left.Features == right.Features &&
		maps.Equal(left.Metadata, right.Metadata) &&
		maps.Equal(left.EnvVars, right.EnvVars)
}

func (r *RuntimeMetricsReporter) reportRuntimeMetrics(snapshots []runtimemetrics.RuntimeMetricSnapshot) {
	for _, snapshot := range snapshots {
		if !r.shouldReportSnapshot(snapshot) {
			continue
		}
		// A snapshot may still be in flight after its process terminated.
		if !snapshot.Removed && !r.snapshotProcessLive(snapshot) {
			r.log.Debug("skipping snapshot for terminated process",
				"pid", snapshot.PID, "service", snapshot.Service.UID)
			continue
		}
		metrics, err := r.reporters.For(&snapshot.Service)
		if err != nil {
			r.log.Debug("creating runtime metric set failed", "pid", snapshot.PID, "error", err)
			continue
		}
		recordRuntimeMetrics(r.ctx, metrics, snapshot)
	}
}

func (r *RuntimeMetricsReporter) snapshotProcessLive(snapshot runtimemetrics.RuntimeMetricSnapshot) bool {
	pid := snapshot.Service.ProcPID
	if snapshot.Histogram != nil {
		pid = snapshot.PID
	}
	if pid == 0 {
		return true
	}
	return r.pidTracker.PIDLiveOrUnknown(pid, snapshot.Service.UID, snapshot.Generation)
}

func (r *RuntimeMetricsReporter) shouldReportSnapshot(snapshot runtimemetrics.RuntimeMetricSnapshot) bool {
	return r.runtimeEnabled.ShouldReport(snapshot)
}

func recordRuntimeMetrics(ctx context.Context, metrics *RuntimeMetrics, snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if metrics == nil {
		return
	}

	if snapshot.Service.SDKLanguage == svc.InstrumentableGolang {
		if snapshot.Histogram != nil && metrics.goHistogramProducer != nil {
			metrics.goHistogramProducer.Update(snapshot)
		}
		if snapshot.Go != nil {
			recordGoRuntimeMetrics(ctx, &metrics.goMetrics, snapshot)
		}
	}
	if snapshot.JVM != nil {
		if !snapshot.Service.ExportModes.CanExportMetrics() || !snapshot.Service.Features.AppRuntime() {
			return
		}
		metrics.jvmMetrics.record(snapshot)
	}
	if snapshot.Nodejs != nil {
		if !snapshot.Service.ExportModes.CanExportMetrics() || !snapshot.Service.Features.AppRuntime() {
			return
		}
		metrics.nodejsMetrics.record(snapshot)
	}
	if snapshot.NodejsGC != nil || snapshot.NodejsHeapSpace != nil {
		if !snapshot.Service.ExportModes.CanExportMetrics() || !snapshot.Service.Features.AppRuntime() {
			return
		}
		metrics.nodejsMetrics.recordV8(snapshot)
	}
	if snapshot.Python != nil {
		if snapshot.Service.SDKLanguage != svc.InstrumentablePython ||
			!snapshot.Service.ExportModes.CanExportMetrics() ||
			!snapshot.Service.Features.AppRuntime() {
			return
		}
		recordPythonRuntimeMetrics(ctx, &metrics.pythonMetrics, snapshot)
	}
}

func recordPythonRuntimeMetrics(
	ctx context.Context,
	metrics *pythonRuntimeMetrics,
	snapshot runtimemetrics.RuntimeMetricSnapshot,
) {
	if metrics == nil || metrics.collections == nil {
		return
	}
	if snapshot.Removed {
		delete(metrics.values, snapshot.PID)
		return
	}
	if metrics.values == nil {
		metrics.values = map[app.PID]*pythonRuntimeMetricValues{}
	}
	previous := metrics.values[snapshot.PID]
	if previous == nil {
		previous = &pythonRuntimeMetricValues{}
		metrics.values[snapshot.PID] = previous
	}

	for generation, values := range snapshot.Python.Generations {
		generationAttr := attribute.KeyValue{Key: attr.CPythonGCGeneration.OTEL(), Value: attribute.IntValue(generation)}
		recordRuntimeCounterWithAttributes(ctx, metrics.collections, &previous.collections[generation],
			values.Collections, generationAttr)
		recordRuntimeCounterWithAttributes(ctx, metrics.collectedObjects, &previous.collectedObjects[generation],
			values.CollectedObjects, generationAttr)
		recordRuntimeCounterWithAttributes(ctx, metrics.uncollectableObjects, &previous.uncollectableObjects[generation],
			values.UncollectableObjects, generationAttr)
	}
}

func recordRuntimeCounterWithAttributes(
	ctx context.Context,
	metric instrument.Int64Counter,
	previous *pythonRuntimeCounterValue,
	current uint64,
	attrs ...attribute.KeyValue,
) {
	option := instrument.WithAttributes(attrs...)
	if !previous.initialized || current < previous.value {
		metric.Add(ctx, int64(current), option)
	} else if delta := current - previous.value; delta > 0 {
		metric.Add(ctx, int64(delta), option)
	}
	previous.value = current
	previous.initialized = true
}

func recordGoRuntimeMetrics(ctx context.Context, metrics *goRuntimeMetrics, snapshot runtimemetrics.RuntimeMetricSnapshot) {
	if snapshot.Go == nil || metrics.memoryLimit == nil {
		return
	}

	recordCurrentRuntimeMetric(ctx, metrics.memoryLimit, &metrics.memoryLimitValue, snapshot.Go.MemoryLimit)
	recordCurrentRuntimeMetric(ctx, metrics.memoryGCGoal, &metrics.memoryGCGoalValue, snapshot.Go.MemoryGCGoal)
	recordRuntimeCounter(ctx, metrics.memoryGCCycles, &metrics.memoryGCCyclesValue, snapshot.Go.GCCycles)
	recordCurrentRuntimeMetricWithAttributes(
		ctx,
		metrics.memoryUsed,
		&metrics.memoryUsedValues,
		"stack",
		snapshot.Go.MemoryUsedStack,
		semconv.GoMemoryTypeStack,
	)
	recordCurrentRuntimeMetricWithAttributes(
		ctx,
		metrics.memoryUsed,
		&metrics.memoryUsedValues,
		"other",
		snapshot.Go.MemoryUsedOther,
		semconv.GoMemoryTypeOther,
	)
	recordRuntimeCounter(ctx, metrics.memoryAllocated, &metrics.memoryAllocatedValue, snapshot.Go.MemoryAllocated)
	recordRuntimeCounter(ctx, metrics.memoryAllocations, &metrics.memoryAllocationsValue, snapshot.Go.MemoryAllocations)
	recordGoRuntimeCPUTime(ctx, metrics, snapshot.Go.CPUTime)
	recordCurrentRuntimeMetric(ctx, metrics.goroutineCount, &metrics.goroutineCountValue, snapshot.Go.GoroutineCount)
	recordCurrentRuntimeMetric(ctx, metrics.processorLimit, &metrics.processorLimitValue, snapshot.Go.ProcessorLimit)
	recordCurrentRuntimeMetric(ctx, metrics.configGOGC, &metrics.configGOGCValue, snapshot.Go.GOGC)
}

func recordCurrentRuntimeMetric(
	ctx context.Context,
	metric instrument.Int64UpDownCounter,
	previous **int64,
	current *int64,
) {
	if current == nil {
		if *previous != nil {
			metric.Add(ctx, -**previous)
			*previous = nil
		}
		metric.Remove(ctx)
		return
	}

	if *previous == nil {
		metric.Add(ctx, *current)
	} else if delta := *current - **previous; delta != 0 {
		metric.Add(ctx, delta)
	}
	value := *current
	*previous = &value
}

func recordRuntimeCounter(
	ctx context.Context,
	metric instrument.Int64Counter,
	previous **uint64,
	current *uint64,
) {
	if current == nil {
		*previous = nil
		metric.Remove(ctx)
		return
	}

	if *previous == nil || *current < **previous {
		metric.Remove(ctx)
		metric.Add(ctx, int64(*current))
	} else if delta := *current - **previous; delta > 0 {
		metric.Add(ctx, int64(delta))
	}
	value := *current
	*previous = &value
}

func recordCurrentRuntimeMetricWithAttributes(
	ctx context.Context,
	metric instrument.Int64UpDownCounter,
	previous *map[string]int64,
	key string,
	current *int64,
	attrs ...attribute.KeyValue,
) {
	if *previous == nil {
		*previous = map[string]int64{}
	}
	options := []instrument.AddOption{instrument.WithAttributes(attrs...)}
	removeOptions := []instrument.RemoveOption{instrument.WithAttributes(attrs...)}

	prev, ok := (*previous)[key]
	if current == nil {
		if ok {
			metric.Add(ctx, -prev, options...)
			delete(*previous, key)
		}
		metric.Remove(ctx, removeOptions...)
		return
	}

	if !ok {
		metric.Add(ctx, *current, options...)
	} else if delta := *current - prev; delta != 0 {
		metric.Add(ctx, delta, options...)
	}
	(*previous)[key] = *current
}

func recordGoRuntimeCPUTime(
	ctx context.Context,
	metrics *goRuntimeMetrics,
	cpu *runtimemetrics.GoRuntimeCPUTimeSnapshot,
) {
	for _, value := range runtimemetrics.GoRuntimeCPUTimeValues(cpu) {
		key := value.State
		attrs := []attribute.KeyValue{semconv.GoCPUStateKey.String(value.State)}
		if value.DetailedState != "" {
			key = value.DetailedState
			attrs = append(attrs, semconv.GoCPUDetailedState(value.DetailedState))
		}

		if cpu == nil {
			removeFloatRuntimeCounterWithAttributes(ctx, metrics.cpuTime, &metrics.cpuTimeValues,
				key, attrs...)
			continue
		}

		recordFloatRuntimeCounterWithAttributes(ctx, metrics.cpuTime, &metrics.cpuTimeValues,
			key, value.Nanoseconds, attrs...)
	}
}

func recordFloatRuntimeCounterWithAttributes(
	ctx context.Context,
	metric instrument.Float64Counter,
	previous *map[string]int64,
	key string,
	current int64,
	attrs ...attribute.KeyValue,
) {
	if *previous == nil {
		*previous = map[string]int64{}
	}
	options := []instrument.AddOption{instrument.WithAttributes(attrs...)}
	removeOptions := []instrument.RemoveOption{instrument.WithAttributes(attrs...)}

	prev, ok := (*previous)[key]
	if !ok || current < prev {
		currentSeconds := float64(current) / float64(time.Second)
		metric.Remove(ctx, removeOptions...)
		metric.Add(ctx, currentSeconds, options...)
	} else if delta := current - prev; delta > 0 {
		metric.Add(ctx, float64(delta)/float64(time.Second), options...)
	}
	(*previous)[key] = current
}

func removeFloatRuntimeCounterWithAttributes(
	ctx context.Context,
	metric instrument.Float64Counter,
	previous *map[string]int64,
	key string,
	attrs ...attribute.KeyValue,
) {
	if *previous != nil {
		delete(*previous, key)
	}
	metric.Remove(ctx, instrument.WithAttributes(attrs...))
}

func (r *RuntimeMetricsReporter) close() {
	go func() {
		if err := r.exporter.Shutdown(r.ctx); err != nil {
			rmlog().Warn("closing runtime metrics provider", "error", err)
			return
		}
		rmlog().Debug("runtime metrics reporter closed")
	}()
}

type runtimeCurrentUpDownCounter struct {
	ctx     context.Context
	metric  instrument.Int64UpDownCounter
	attrs   []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue]
	entries *expire.ExpiryMap[*runtimeCurrentUpDownCounterEntry]
	log     *slog.Logger

	clock          expire.Clock
	lastExpiration time.Time
	ttl            time.Duration
}

type runtimeCurrentUpDownCounterEntry struct {
	attrs       attribute.Set
	value       int64
	initialized bool
}

func newRuntimeCurrentUpDownCounter(
	ctx context.Context,
	metric instrument.Int64UpDownCounter,
	attrs []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue],
	clock expire.Clock,
	ttl time.Duration,
) *runtimeCurrentUpDownCounter {
	return &runtimeCurrentUpDownCounter{
		ctx:            ctx,
		metric:         metric,
		attrs:          attrs,
		entries:        expire.NewExpiryMap[*runtimeCurrentUpDownCounterEntry](clock, ttl),
		log:            plog().With("type", fmt.Sprintf("%T", metric)),
		clock:          clock,
		lastExpiration: clock(),
		ttl:            ttl,
	}
}

func (c *runtimeCurrentUpDownCounter) Record(snapshot runtimemetrics.RuntimeMetricSnapshot, value int64) {
	now := c.clock()
	if now.Sub(c.lastExpiration) >= c.ttl {
		c.removeOutdated(c.ctx)
		c.lastExpiration = now
	}

	recordAttrs, attrValues := runtimeAttributeSet(c.attrs, snapshot)
	entry := c.entries.GetOrCreate(attrValues, func() *runtimeCurrentUpDownCounterEntry {
		c.log.Debug("storing new metric label set", "labelValues", attrValues)
		return &runtimeCurrentUpDownCounterEntry{attrs: recordAttrs}
	})

	delta := value - entry.value
	if !entry.initialized || delta != 0 {
		c.metric.Add(c.ctx, delta, instrument.WithAttributeSet(entry.attrs))
	}
	entry.value = value
	entry.initialized = true
}

func (c *runtimeCurrentUpDownCounter) removeOutdated(ctx context.Context) {
	for _, entry := range c.entries.DeleteExpired() {
		c.metric.Add(ctx, -entry.value, instrument.WithAttributeSet(entry.attrs))
		c.metric.Remove(ctx, instrument.WithAttributeSet(entry.attrs))
	}
}

func runtimeAttributeSet(
	fields []attributes.Field[runtimemetrics.RuntimeMetricSnapshot, attribute.KeyValue],
	snapshot runtimemetrics.RuntimeMetricSnapshot,
) (attribute.Set, []string) {
	keyVals := make([]attribute.KeyValue, 0, len(fields))
	vals := make([]string, 0, len(fields))

	for _, field := range fields {
		kv := sanitizeKeyValue(field.Get(snapshot))
		keyVals = append(keyVals, kv)
		vals = append(vals, kv.Value.Emit())
	}

	return attribute.NewSet(keyVals...), vals
}
