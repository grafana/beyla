// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// Max interval before reading stale available bytes from the ring buffer
const flushInterval = 3 * time.Second

// ringBufReader interface extracts the used methods from ringbuf.Reader for proper
// dependency injection during tests
type ringBufReader interface {
	io.Closer
	Read() (ringbuf.Record, error)
	ReadInto(*ringbuf.Record) error
	AvailableBytes() int
	Flush() error
}

// readerFactory instantiates a ringBufReader from a ring buffer. In unit tests, we can
// replace this function by a mock/dummy.
var readerFactory = func(rb *ebpf.Map) (ringBufReader, error) {
	return ringbuf.NewReader(rb)
}

// RecordParserFunc reads one ring buffer record and returns (item, ignore, err).
type RecordParserFunc[T any] func(*ringbuf.Record) (T, bool, error)

// BatchFilterFunc is an optional batch-level filter applied at flush time (nil = identity).
type BatchFilterFunc[T any] func([]T) []T

// ringBufForwarder[T] handles the common loop: read -> parse -> batch -> flush
// it's generic so it can be used for both request.Span (appolly) and ebpf.Record (statsolly)
type ringBufForwarder[T any] struct {
	cfg        *config.EBPFTracer
	logger     *slog.Logger
	ringbuffer *ebpf.Map
	closers    []io.Closer
	items      []T
	itemsLen   int
	access     sync.Mutex
	ticker     *time.Ticker

	// parse reads one record and returns (item, ignore, err).
	// Callers close over whatever context they need (parse ctx, filter, etc.)
	parse RecordParserFunc[T]

	// filter is optional batch-level filter applied at flush time (nil = identity)
	// in appolly, filter the input spans, eliminating these from processes whose PID
	// belong to a process that does not match the discovery policies
	filter BatchFilterFunc[T]

	// metrics is optional (nil = no-op)
	metrics    imetrics.Reporter
	lastReadAt time.Time
}

// AlreadyForwarded is used in the case when a second tracer tries to set up the
// shared ring buffer and so it blocks until the context is cancelled
func (rbf *ringBufForwarder[T]) AlreadyForwarded(ctx context.Context) {
	<-ctx.Done()
}

// SharedRingbuf returns a function that reads events from a shared input ring buffer,
// accumulates them into an internal buffer, and forwards them to an output events channel.
// If the shared ring buffer forwarder already exists, subsequent calls return a no-op
// that simply waits for context cancellation.
func SharedRingbuf[T any](
	eventContext *EBPFEventContext,
	cfg *config.EBPFTracer,
	ringbuffer *ebpf.Map,
	parse RecordParserFunc[T],
	filter BatchFilterFunc[T], // nil = no batch filter
	logger *slog.Logger,
	metrics imetrics.Reporter,
) func(context.Context, []io.Closer, *msg.Queue[[]T]) {
	eventContext.RingBufLock.Lock()
	defer eventContext.RingBufLock.Unlock()

	if eventContext.SharedRingBuffer != nil {
		logger.Debug("reusing ringbuf forwarder")
		sf := eventContext.SharedRingBuffer
		return func(ctx context.Context, _ []io.Closer, _ *msg.Queue[[]T]) {
			sf.AlreadyForwarded(ctx)
		}
	}

	rbf := ringBufForwarder[T]{
		cfg: cfg, logger: logger, ringbuffer: ringbuffer,
		closers: nil, parse: parse,
		filter: filter, metrics: metrics,
	}
	eventContext.SharedRingBuffer = &rbf
	return rbf.sharedReadAndForward
}

func ForwardRingbuf[T any](
	cfg *config.EBPFTracer,
	ringbuffer *ebpf.Map,
	parse RecordParserFunc[T],
	filter BatchFilterFunc[T], // nil = no batch filter
	logger *slog.Logger,
	metrics imetrics.Reporter,
	closers ...io.Closer,
) func(context.Context, *msg.Queue[[]T]) {
	rbf := ringBufForwarder[T]{
		cfg: cfg, logger: logger, ringbuffer: ringbuffer,
		closers: closers, parse: parse,
		filter: filter, metrics: metrics,
	}
	return rbf.readAndForward
}

func (rbf *ringBufForwarder[T]) sharedReadAndForward(ctx context.Context, closers []io.Closer, out *msg.Queue[[]T]) {
	rbf.logger.Debug("start reading and forwarding")
	// BPF will send each measured item via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating perf reader. Exiting", "error", err)
		return
	}
	rbf.items = make([]T, rbf.cfg.BatchLength)
	rbf.itemsLen = 0

	// If the underlying context is closed, it closes the objects we have allocated for this bpf program
	go rbf.bgListenSharedContextCancelation(ctx, closers, eventsReader)
	rbf.readAndForwardInner(ctx, eventsReader, out)
}

func (rbf *ringBufForwarder[T]) readAndForward(ctx context.Context, out *msg.Queue[[]T]) {
	rbf.logger.Debug("start reading and forwarding")
	// BPF will send each measured item via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating perf reader. Exiting", "error", err)
		return
	}
	rbf.closers = append(rbf.closers, eventsReader)
	defer rbf.closeAllResources()

	rbf.items = make([]T, rbf.cfg.BatchLength)
	rbf.itemsLen = 0

	// If the underlying context is closed, it closes the events reader
	// so the function can exit.
	go rbf.bgListenContextCancelation(ctx, eventsReader)
	rbf.readAndForwardInner(ctx, eventsReader, out)
}

func (rbf *ringBufForwarder[T]) flushOnAvailableBytes(ctx context.Context, eventsReader ringBufReader) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			available := eventsReader.AvailableBytes()
			if available > 0 && time.Since(rbf.lastReadAt) > flushInterval {
				err := eventsReader.Flush()
				rbf.logger.Debug("flushing ringbuf", "available_bytes", available, "flush_err", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (rbf *ringBufForwarder[T]) readAndForwardInner(ctx context.Context, eventsReader ringBufReader, out *msg.Queue[[]T]) {
	// Forwards periodically on timeout, if the batch is not full
	if rbf.cfg.BatchTimeout > 0 {
		rbf.ticker = time.NewTicker(rbf.cfg.BatchTimeout)
		go rbf.bgFlushOnTimeout(ctx, out)
	}

	// Ensure we periodically flush any pending bytes
	go rbf.flushOnAvailableBytes(ctx, eventsReader)

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
	for {
		err := eventsReader.ReadInto(&record)
		rbf.lastReadAt = time.Now()
		if err != nil {
			if errors.Is(err, ringbuf.ErrFlushed) {
				rbf.logger.Debug("ring buffer already flushed")
				continue
			}
			if errors.Is(err, ringbuf.ErrClosed) {
				rbf.logger.Debug("ring buffer is closed")
				return
			}
			rbf.logger.Error("error reading from perf reader", "error", err)
			continue
		}
		rbf.processAndForward(ctx, record, out)
	}
}

func (rbf *ringBufForwarder[T]) processAndForward(ctx context.Context, record ringbuf.Record, out *msg.Queue[[]T]) {
	rbf.access.Lock()
	defer rbf.access.Unlock()
	item, ignore, err := rbf.parse(&record)
	if err != nil {
		rbf.logger.Debug("error parsing perf event", "error", err)
		return
	}
	if ignore {
		return
	}
	rbf.items[rbf.itemsLen] = item
	rbf.itemsLen++
	if rbf.itemsLen == rbf.cfg.BatchLength {
		rbf.logger.Debug("submitting batch (full)", "len", rbf.itemsLen)
		rbf.flushEvents(ctx, out)
		if rbf.ticker != nil {
			rbf.ticker.Reset(rbf.cfg.BatchTimeout)
		}
	}
}

func (rbf *ringBufForwarder[T]) flushEvents(ctx context.Context, out *msg.Queue[[]T]) {
	if rbf.metrics != nil {
		rbf.metrics.TracerFlush(rbf.itemsLen)
	}
	batch := rbf.items[:rbf.itemsLen]
	if rbf.filter != nil {
		batch = rbf.filter(batch)
	}
	out.SendCtx(ctx, batch)
	rbf.items = make([]T, rbf.cfg.BatchLength)
	rbf.itemsLen = 0
}

func (rbf *ringBufForwarder[T]) bgFlushOnTimeout(ctx context.Context, out *msg.Queue[[]T]) {
	for {
		select {
		case <-ctx.Done():
			return

		case <-rbf.ticker.C:
			rbf.access.Lock()
			if rbf.itemsLen > 0 {
				rbf.logger.Debug("submitting items on timeout", "len", rbf.itemsLen)
				rbf.flushEvents(ctx, out)
			}
			rbf.access.Unlock()
		}
	}
}

func (rbf *ringBufForwarder[T]) bgListenContextCancelation(ctx context.Context, eventsReader ringBufReader) {
	<-ctx.Done()
	rbf.logger.Debug("context is cancelled. Closing events reader")
	_ = eventsReader.Close()
}

func (rbf *ringBufForwarder[T]) bgListenSharedContextCancelation(ctx context.Context, closers []io.Closer, eventsReader ringBufReader) {
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

func (rbf *ringBufForwarder[T]) closeAllResources() {
	rbf.logger.Debug("closing eBPF resources", "len", len(rbf.closers))
	// Often there are hundreds of closers, and don't have time to sequentially close within the
	// shutdown grace period. Closing them in parallel
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
