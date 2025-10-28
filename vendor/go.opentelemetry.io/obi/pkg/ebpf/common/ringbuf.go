// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// ringBufReader interface extracts the used methods from ringbuf.Reader for proper
// dependency injection during tests
type ringBufReader interface {
	io.Closer
	Read() (ringbuf.Record, error)
	ReadInto(*ringbuf.Record) error
}

// readerFactory instantiates a ringBufReader from a ring buffer. In unit tests, we can
// replace this function by a mock/dummy.
var readerFactory = func(rb *ebpf.Map) (ringBufReader, error) {
	return ringbuf.NewReader(rb)
}

type ringBufForwarder struct {
	cfg        *config.EBPFTracer
	logger     *slog.Logger
	ringbuffer *ebpf.Map
	closers    []io.Closer
	spans      []request.Span
	spansLen   int
	access     sync.Mutex
	ticker     *time.Ticker
	reader     func(*EBPFParseContext, *config.EBPFTracer, *ringbuf.Record, ServiceFilter) (request.Span, bool, error)
	// filter the input spans, eliminating these from processes whose PID
	// belong to a process that does not match the discovery policies
	filter       ServiceFilter
	metrics      imetrics.Reporter
	parseContext *EBPFParseContext
}

// SharedRingbuf returns a function reads HTTPRequestTraces from an input ring buffer, accumulates them into an
// internal buffer, and forwards them to an output events channel, previously converted to request.Span
// instances.
func SharedRingbuf(
	eventContext *EBPFEventContext,
	parseContext *EBPFParseContext,
	cfg *config.EBPFTracer,
	filter ServiceFilter,
	ringbuffer *ebpf.Map,
	metrics imetrics.Reporter,
) func(context.Context, []io.Closer, *msg.Queue[[]request.Span]) {
	eventContext.RingBufLock.Lock()
	defer eventContext.RingBufLock.Unlock()

	log := slog.With("component", "ringbuf.Tracer")

	if eventContext.SharedRingBuffer != nil {
		log.Debug("reusing ringbuf forwarder")
		return eventContext.SharedRingBuffer.alreadyForwarded
	}

	rbf := ringBufForwarder{
		cfg: cfg, logger: log, ringbuffer: ringbuffer,
		closers: nil, reader: ReadBPFTraceAsSpan,
		filter: filter, metrics: metrics,
		parseContext: parseContext,
	}
	eventContext.SharedRingBuffer = &rbf
	return eventContext.SharedRingBuffer.sharedReadAndForward
}

func ForwardRingbuf(
	cfg *config.EBPFTracer,
	ringbuffer *ebpf.Map,
	filter ServiceFilter,
	reader func(*EBPFParseContext, *config.EBPFTracer, *ringbuf.Record, ServiceFilter) (request.Span, bool, error),
	logger *slog.Logger,
	metrics imetrics.Reporter,
	closers ...io.Closer,
) func(context.Context, *msg.Queue[[]request.Span]) {
	rbf := ringBufForwarder{
		cfg: cfg, logger: logger, ringbuffer: ringbuffer,
		closers: closers, reader: reader,
		filter: filter, metrics: metrics,
		parseContext: NewEBPFParseContext(cfg),
	}
	return rbf.readAndForward
}

func (rbf *ringBufForwarder) sharedReadAndForward(ctx context.Context, closers []io.Closer, spansChan *msg.Queue[[]request.Span]) {
	rbf.logger.Debug("start reading and forwarding")
	// BPF will send each measured trace via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating perf reader. Exiting", "error", err)
		return
	}
	rbf.spans = make([]request.Span, rbf.cfg.BatchLength)
	rbf.spansLen = 0

	// If the underlying context is closed, it closes the objects we have allocated for this bpf program
	go rbf.bgListenSharedContextCancelation(ctx, closers, eventsReader)
	rbf.readAndForwardInner(ctx, eventsReader, spansChan)
}

func (rbf *ringBufForwarder) readAndForward(ctx context.Context, spansChan *msg.Queue[[]request.Span]) {
	rbf.logger.Debug("start reading and forwarding")
	// BPF will send each measured trace via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating perf reader. Exiting", "error", err)
		return
	}
	rbf.closers = append(rbf.closers, eventsReader)
	defer rbf.closeAllResources()

	rbf.spans = make([]request.Span, rbf.cfg.BatchLength)
	rbf.spansLen = 0

	// If the underlying context is closed, it closes the events reader
	// so the function can exit.
	go rbf.bgListenContextCancelation(ctx, eventsReader)
	rbf.readAndForwardInner(ctx, eventsReader, spansChan)
}

func (rbf *ringBufForwarder) readAndForwardInner(ctx context.Context, eventsReader ringBufReader, spansChan *msg.Queue[[]request.Span]) {
	// Forwards periodically on timeout, if the batch is not full
	if rbf.cfg.BatchTimeout > 0 {
		rbf.ticker = time.NewTicker(rbf.cfg.BatchTimeout)
		go rbf.bgFlushOnTimeout(ctx, spansChan)
	}

	// Main loop:
	// 1. Listen for content in the ring buffer
	// 2. Decode binary data into HTTPRequestTrace instance
	// 3. Accumulate the HTTPRequestTrace into a batch slice
	// 4. When the length of the batch slice reaches cfg.BatchLength,
	//    submit it to the next stage of the pipeline

	// We just log the first ring buffer read to check that the eBPF side is sending stuff
	// Logging each message adds few information and a lot of noise to the debug logs
	// in production systems with thousands of messages per second
	rbf.logger.Debug("starting to read ring buffer")

	var record ringbuf.Record
	err := eventsReader.ReadInto(&record)
	for {
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				rbf.logger.Debug("ring buffer is closed")
				return
			}
			rbf.logger.Error("error reading from perf reader", "error", err)
			continue
		}
		rbf.processAndForward(record, spansChan)

		// read another event before the next loop iteration
		err = eventsReader.ReadInto(&record)
	}
}

func (rbf *ringBufForwarder) alreadyForwarded(ctx context.Context, _ []io.Closer, _ *msg.Queue[[]request.Span]) {
	<-ctx.Done()
}

func (rbf *ringBufForwarder) processAndForward(record ringbuf.Record, spansChan *msg.Queue[[]request.Span]) {
	rbf.access.Lock()
	defer rbf.access.Unlock()
	s, ignore, err := rbf.reader(rbf.parseContext, rbf.cfg, &record, rbf.filter)
	if err != nil {
		rbf.logger.Error("error parsing perf event", "error", err)
		return
	}
	if ignore {
		return
	}
	if !s.IsValid() {
		rbf.logger.Debug("invalid span", "span", s)
		return
	}
	rbf.spans[rbf.spansLen] = s
	// we need to decorate each span with the tracer's service name
	// if this information is not forwarded from eBPF
	rbf.spansLen++
	if rbf.spansLen == rbf.cfg.BatchLength {
		rbf.logger.Debug("submitting traces after batch is full", "len", rbf.spansLen)
		rbf.flushEvents(spansChan)
		if rbf.ticker != nil {
			rbf.ticker.Reset(rbf.cfg.BatchTimeout)
		}
	}
}

func (rbf *ringBufForwarder) flushEvents(spansChan *msg.Queue[[]request.Span]) {
	rbf.metrics.TracerFlush(rbf.spansLen)
	spansChan.Send(rbf.filter.Filter(rbf.spans[:rbf.spansLen]))
	rbf.spans = make([]request.Span, rbf.cfg.BatchLength)
	rbf.spansLen = 0
}

func (rbf *ringBufForwarder) bgFlushOnTimeout(ctx context.Context, spansChan *msg.Queue[[]request.Span]) {
	for {
		select {
		case <-ctx.Done():
			return

		case <-rbf.ticker.C:
			rbf.access.Lock()
			if rbf.spansLen > 0 {
				rbf.logger.Debug("submitting traces on timeout", "len", rbf.spansLen)
				rbf.flushEvents(spansChan)
			}
			rbf.access.Unlock()
		}
	}
}

func (rbf *ringBufForwarder) bgListenContextCancelation(ctx context.Context, eventsReader ringBufReader) {
	<-ctx.Done()
	rbf.logger.Debug("context is cancelled. Closing events reader")
	_ = eventsReader.Close()
}

func (rbf *ringBufForwarder) bgListenSharedContextCancelation(ctx context.Context, closers []io.Closer, eventsReader ringBufReader) {
	<-ctx.Done()
	rbf.logger.Debug("context is cancelled. Closing eBPF resources", "len", len(closers))
	// Often there are hundreds of closers, and don't have time to sequentially close within the
	// shutdown grace period. Closing them in parallel
	wg := sync.WaitGroup{}
	wg.Add(len(closers))
	for i := range closers {
		c := closers[i]
		go func() {
			defer wg.Done()
			_ = c.Close()
		}()
	}
	wg.Wait()
	rbf.logger.Debug("closing events reader")
	_ = eventsReader.Close()

	rbf.logger.Debug("the eBPF resources are closed")
}

func (rbf *ringBufForwarder) closeAllResources() {
	rbf.logger.Debug("closing eBPF resources", "len", len(rbf.closers))
	// Often there are hundreds of closers, and don't have time to sequentially close within the
	// shutdowm grace period. Closing them in parallel
	wg := sync.WaitGroup{}
	wg.Add(len(rbf.closers))
	for i := range rbf.closers {
		c := rbf.closers[i]
		go func() {
			defer wg.Done()
			_ = c.Close()
			rbf.logger.Debug("eBPF resource closed", "num", i)
		}()
	}
	wg.Wait()
	rbf.logger.Debug("the eBPF resources are closed")
}
