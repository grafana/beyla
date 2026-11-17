// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/shutdown"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

// Max interval before reading stale available bytes from the ring buffer
const flushInterval = 3 * time.Second

// How long the reader must have gone without consuming a record before a flush
// is issued on its behalf. This has to stay strictly below flushInterval: a
// flush wakes the reader, so the reads it causes are timestamped just after the
// tick that issued it. Measuring idleness over the whole interval therefore
// lets every flush suppress the tick that should follow it, halving the flush
// rate and leaving records pending for two intervals instead of one.
const readerStalledAfter = flushInterval / 2

const maxShutdownDrain = 2 * time.Second

func shutdownDrainTimeout(shutdownTimeout time.Duration) time.Duration {
	return min(maxShutdownDrain, shutdownTimeout/4)
}

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

type ContextRecordParserFunc[T any] func(context.Context, *ringbuf.Record) (T, bool, error)

// BatchFilterFunc is an optional filter applied to each parsed group before batching (nil = identity).
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
	readerLock sync.Mutex
	ticker     *time.Ticker

	// parse reads one record and returns (item, ignore, err).
	// Callers close over whatever context they need (parse ctx, filter, etc.)
	parse ContextRecordParserFunc[T]

	// filter is optional and runs on each parsed group before it enters the batch
	// (nil = identity). In appolly it drops the spans of processes that do not match
	// the discovery policies and decorates the rest while their process is still known
	filter BatchFilterFunc[T]

	// metrics is optional (nil = no-op)
	metrics imetrics.Reporter
	// lastReadAtUnixNano is updated by the read loop and observed by the periodic flusher.
	lastReadAtUnixNano atomic.Int64
	draining           atomic.Bool
	drainTimeout       time.Duration
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
	filter BatchFilterFunc[T], // nil = no filter
	logger *slog.Logger,
	metrics imetrics.Reporter,
) func(context.Context, []io.Closer, *msg.Queue[[]T]) {
	return sharedRingbuf(eventContext, cfg, maxShutdownDrain, ringbuffer, ignoreContext(parse), filter, logger, metrics)
}

func SharedRingbufWithDrainContext[T any](
	eventContext *EBPFEventContext,
	cfg *config.EBPFTracer,
	shutdownTimeout time.Duration,
	ringbuffer *ebpf.Map,
	parse ContextRecordParserFunc[T],
	filter BatchFilterFunc[T], // nil = no filter
	logger *slog.Logger,
	metrics imetrics.Reporter,
) func(context.Context, []io.Closer, *msg.Queue[[]T]) {
	return sharedRingbuf(eventContext, cfg, shutdownDrainTimeout(shutdownTimeout), ringbuffer, parse, filter, logger, metrics)
}

func sharedRingbuf[T any](
	eventContext *EBPFEventContext,
	cfg *config.EBPFTracer,
	drainTimeout time.Duration,
	ringbuffer *ebpf.Map,
	parse ContextRecordParserFunc[T],
	filter BatchFilterFunc[T],
	logger *slog.Logger,
	metrics imetrics.Reporter,
) func(context.Context, []io.Closer, *msg.Queue[[]T]) {
	eventContext.RingBufLock.Lock()
	defer eventContext.RingBufLock.Unlock()

	if eventContext.SharedRingBuffer != nil {
		logger.Debug("reusing ringbuf forwarder")
		sf := eventContext.SharedRingBuffer
		return func(ctx context.Context, closers []io.Closer, _ *msg.Queue[[]T]) {
			sf.AlreadyForwarded(ctx)
			closeAll(logger, closers)
		}
	}

	rbf := ringBufForwarder[T]{
		cfg: cfg, drainTimeout: drainTimeout,
		logger: logger, ringbuffer: ringbuffer,
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
	filter BatchFilterFunc[T], // nil = no filter
	logger *slog.Logger,
	metrics imetrics.Reporter,
	closers ...io.Closer,
) func(context.Context, *msg.Queue[[]T]) {
	return forwardRingbuf(cfg, maxShutdownDrain, ringbuffer, ignoreContext(parse), filter, logger, metrics, closers...)
}

func ForwardRingbufWithDrainContext[T any](
	cfg *config.EBPFTracer,
	shutdownTimeout time.Duration,
	ringbuffer *ebpf.Map,
	parse ContextRecordParserFunc[T],
	filter BatchFilterFunc[T], // nil = no filter
	logger *slog.Logger,
	metrics imetrics.Reporter,
	closers ...io.Closer,
) func(context.Context, *msg.Queue[[]T]) {
	return forwardRingbuf(cfg, shutdownDrainTimeout(shutdownTimeout), ringbuffer, parse, filter, logger, metrics, closers...)
}

func forwardRingbuf[T any](
	cfg *config.EBPFTracer,
	drainTimeout time.Duration,
	ringbuffer *ebpf.Map,
	parse ContextRecordParserFunc[T],
	filter BatchFilterFunc[T],
	logger *slog.Logger,
	metrics imetrics.Reporter,
	closers ...io.Closer,
) func(context.Context, *msg.Queue[[]T]) {
	rbf := ringBufForwarder[T]{
		cfg: cfg, drainTimeout: drainTimeout,
		logger: logger, ringbuffer: ringbuffer,
		closers: closers, parse: parse,
		filter: filter, metrics: metrics,
	}
	return rbf.readAndForward
}

func ignoreContext[T any](parse RecordParserFunc[T]) ContextRecordParserFunc[T] {
	return func(_ context.Context, record *ringbuf.Record) (T, bool, error) {
		return parse(record)
	}
}

func (rbf *ringBufForwarder[T]) sharedReadAndForward(ctx context.Context, closers []io.Closer, out *msg.Queue[[]T]) {
	rbf.logger.Debug("start reading and forwarding")
	endDrain := shutdown.RegisterReader(ctx)
	defer endDrain()
	// BPF will send each measured item via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating ring buffer reader. Exiting", "error", err)
		return
	}
	// If the underlying context is closed, it closes the objects we have allocated for this bpf program
	// once the pending events are drained.
	// We wait for the closer goroutine to finish before returning so that callers (e.g. Instrumenter.stop)
	// do not signal completion while eBPF resources are still being torn down.
	drainCtx, cancelDrain := rbf.drainContext(ctx)
	var closerDone sync.WaitGroup
	closerDone.Go(func() {
		rbf.bgListenSharedContextCancelation(ctx, drainCtx, closers, eventsReader)
	})
	rbf.readAndForwardInner(ctx, drainCtx, eventsReader, out)
	endDrain()
	cancelDrain()
	closerDone.Wait()
}

func (rbf *ringBufForwarder[T]) readAndForward(ctx context.Context, out *msg.Queue[[]T]) {
	rbf.logger.Debug("start reading and forwarding")
	endDrain := shutdown.RegisterReader(ctx)
	defer endDrain()
	// BPF will send each measured item via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating ring buffer reader. Exiting", "error", err)
		return
	}
	drainCtx, cancelDrain := rbf.drainContext(ctx)
	defer cancelDrain()
	rbf.closers = append(rbf.closers, eventsReader)
	defer rbf.closeAllResources()

	// If the underlying context is closed, it closes the events reader
	// once the pending events are drained, so the function can exit.
	go rbf.bgListenContextCancelation(ctx, drainCtx, eventsReader)
	rbf.readAndForwardInner(ctx, drainCtx, eventsReader, out)
	endDrain()
}

func (rbf *ringBufForwarder[T]) drainContext(ctx context.Context) (context.Context, context.CancelFunc) {
	drainCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, func() {
		time.AfterFunc(rbf.drainTimeout, cancel)
	})
	return drainCtx, func() {
		stop()
		cancel()
	}
}

func (rbf *ringBufForwarder[T]) flushOnAvailableBytes(ctx context.Context, eventsReader ringBufReader) {
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if ctx.Err() != nil {
				continue
			}

			rbf.readerLock.Lock()
			if ctx.Err() != nil {
				rbf.readerLock.Unlock()
				continue
			}
			available := eventsReader.AvailableBytes()
			if available > 0 && rbf.hasPendingReadIdleSince(time.Now(), readerStalledAfter) {
				err := eventsReader.Flush()
				rbf.logger.Debug("flushing ringbuf", "available_bytes", available, "flush_err", err)
			}
			rbf.readerLock.Unlock()
		case <-ctx.Done():
			rbf.flushForShutdown(eventsReader)
			return
		}
	}
}

func (rbf *ringBufForwarder[T]) flushForShutdown(eventsReader ringBufReader) {
	rbf.draining.Store(true)
	rbf.readerLock.Lock()
	err := eventsReader.Flush()
	rbf.readerLock.Unlock()
	rbf.logger.Debug("draining ringbuf before shutdown", "flush_err", err)
}

func (rbf *ringBufForwarder[T]) readAndForwardInner(ctx, drainCtx context.Context, eventsReader ringBufReader, out *msg.Queue[[]T]) {
	rbf.items = make([]T, rbf.cfg.BatchLength)
	rbf.itemsLen = 0

	if rbf.cfg.BatchTimeout > 0 {
		rbf.ticker = time.NewTicker(rbf.cfg.BatchTimeout)
		go rbf.bgFlushOnTimeout(drainCtx, out)
	}
	go rbf.flushOnAvailableBytes(ctx, eventsReader)

	// 2x: one batch for the parser to work on, one for the reader to fill concurrently.
	// Smaller would stall the reader while waiting for the parser to finish.
	poolSize := 2 * rbf.cfg.BatchLength
	records := make([]ringbuf.Record, poolSize)
	freeIdx := make(chan int, poolSize)
	workIdx := make(chan int, poolSize)
	for i := range poolSize {
		freeIdx <- i
	}

	parserDone := make(chan struct{})
	go func() {
		defer close(parserDone)
		rbf.parserLoop(drainCtx, records, freeIdx, workIdx, out)
	}()

	rbf.logger.Debug("starting to read ring buffer")
	rbf.readerLoop(drainCtx, eventsReader, records, freeIdx, workIdx)
	select {
	case <-parserDone:
	case <-drainCtx.Done():
		rbf.logger.Debug("parser did not finish within the shutdown drain timeout")
	}
	rbf.flushPendingItems(drainCtx, out)
}

func (rbf *ringBufForwarder[T]) readerLoop(
	ctx context.Context,
	eventsReader ringBufReader,
	records []ringbuf.Record,
	freeIdx chan int,
	workIdx chan<- int,
) {
	defer close(workIdx)

	for {
		var i int
		select {
		case <-ctx.Done():
			return
		case i = <-freeIdx:
		default:
			rbf.logger.Debug("reader stalled: record pool exhausted",
				"pool_size", len(records), "pending_parse", len(workIdx))
			select {
			case <-ctx.Done():
				return
			case i = <-freeIdx:
			}
		}

		if !rbf.fillAndDispatch(ctx, i, eventsReader, records, freeIdx, workIdx) {
			return
		}
	}
}

func (rbf *ringBufForwarder[T]) fillAndDispatch(
	ctx context.Context,
	i int,
	eventsReader ringBufReader,
	records []ringbuf.Record,
	freeIdx chan int,
	workIdx chan<- int,
) bool {
	if err := eventsReader.ReadInto(&records[i]); err != nil {
		freeIdx <- i
		switch {
		case errors.Is(err, ringbuf.ErrFlushed):
			rbf.logger.Debug("ring buffer already flushed", "draining", rbf.draining.Load())
			return !rbf.draining.Load()
		case errors.Is(err, ringbuf.ErrClosed):
			rbf.logger.Debug("ring buffer is closed")
			return false
		default:
			rbf.logger.Error("error reading from ring buffer", "error", err)
			return true
		}
	}

	rbf.storeLastReadAt(time.Now())

	select {
	case workIdx <- i:
		return true
	case <-ctx.Done():
		return false
	}
}

func (rbf *ringBufForwarder[T]) parserLoop(
	ctx context.Context,
	records []ringbuf.Record,
	freeIdx chan<- int,
	workIdx <-chan int,
	out *msg.Queue[[]T],
) {
	pending := make([]int, 0, cap(workIdx))
	parsed := make([]T, 0, cap(workIdx))

	for {
		pending = pending[:0]
		parsed = parsed[:0]

		// Block until at least one record is ready.
		select {
		case <-ctx.Done():
			return
		case i, ok := <-workIdx:
			if !ok {
				return
			}
			pending = append(pending, i)
		}

		if depth := len(workIdx); depth == cap(workIdx)-1 {
			rbf.logger.Debug("parser falling behind: work queue full", "depth", depth+1)
		}

		// Drain any additional records that are already waiting.
		for {
			select {
			case i, ok := <-workIdx:
				if ok {
					pending = append(pending, i)
					continue
				}
			default:
			}
			break
		}

		// Parse outside the lock, return each slot to the pool immediately.
		for _, i := range pending {
			item, ignore, err := rbf.parse(ctx, &records[i])
			freeIdx <- i
			if err != nil {
				rbf.logger.Debug("error parsing ring buffer event", "error", err)
				continue
			}
			if !ignore {
				parsed = append(parsed, item)
			}
		}

		// filter into a separate slice so parsed keeps its capacity across iterations
		kept := parsed
		if rbf.filter != nil {
			kept = rbf.filter(parsed)
		}
		if len(kept) == 0 {
			continue
		}

		// Lock once to enqueue the whole batch.
		rbf.access.Lock()
		for _, item := range kept {
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
		rbf.access.Unlock()
	}
}

func (rbf *ringBufForwarder[T]) storeLastReadAt(t time.Time) {
	rbf.lastReadAtUnixNano.Store(t.UnixNano())
}

func (rbf *ringBufForwarder[T]) hasPendingReadIdleSince(now time.Time, interval time.Duration) bool {
	lastReadAtUnixNano := rbf.lastReadAtUnixNano.Load()
	if lastReadAtUnixNano == 0 {
		return true
	}

	return now.Sub(time.Unix(0, lastReadAtUnixNano)) > interval
}

func (rbf *ringBufForwarder[T]) flushEvents(ctx context.Context, out *msg.Queue[[]T]) {
	if rbf.metrics != nil {
		rbf.metrics.TracerFlush(rbf.itemsLen)
	}
	out.SendCtx(ctx, rbf.items[:rbf.itemsLen])
	rbf.items = make([]T, rbf.cfg.BatchLength)
	rbf.itemsLen = 0
}

func (rbf *ringBufForwarder[T]) bgFlushOnTimeout(ctx context.Context, out *msg.Queue[[]T]) {
	for {
		select {
		case <-ctx.Done():
			return

		case <-rbf.ticker.C:
			rbf.flushPendingItems(ctx, out)
		}
	}
}

func (rbf *ringBufForwarder[T]) flushPendingItems(ctx context.Context, out *msg.Queue[[]T]) {
	rbf.access.Lock()
	defer rbf.access.Unlock()
	if rbf.itemsLen > 0 {
		rbf.logger.Debug("submitting pending items", "len", rbf.itemsLen)
		rbf.flushEvents(ctx, out)
	}
}

func (rbf *ringBufForwarder[T]) bgListenContextCancelation(ctx, drainCtx context.Context, eventsReader ringBufReader) {
	<-ctx.Done()
	<-drainCtx.Done()
	rbf.logger.Debug("context is cancelled. Closing events reader")
	rbf.readerLock.Lock()
	_ = eventsReader.Close()
	rbf.readerLock.Unlock()
}

func (rbf *ringBufForwarder[T]) bgListenSharedContextCancelation(ctx, drainCtx context.Context, closers []io.Closer, eventsReader ringBufReader) {
	<-ctx.Done()
	<-drainCtx.Done()
	rbf.logger.Debug("context is cancelled. Closing eBPF resources", "len", len(closers))
	// Close the events reader before the eBPF objects so a readerLoop that did not
	// finish draining within drainTimeout unblocks immediately via ErrClosed,
	// rather than waiting for potentially hundreds of eBPF closers to finish.
	rbf.logger.Debug("closing events reader")
	rbf.readerLock.Lock()
	_ = eventsReader.Close()
	rbf.readerLock.Unlock()
	closeAll(rbf.logger, closers)
}

func (rbf *ringBufForwarder[T]) closeAllResources() {
	closeAll(rbf.logger, rbf.closers)
}

// closeAll closes in parallel: the kernel waits for RCU grace periods per probe
// and there is no time to serialize hundreds of them within the shutdown grace period
func closeAll(logger *slog.Logger, closers []io.Closer) {
	logger.Debug("closing eBPF resources", "len", len(closers))
	_ = CloseResources(closers...)
	logger.Debug("the eBPF resources are closed")
}

// CloseResources closes eBPF resources in parallel so each resource does not
// wait for a separate RCU grace period.
func CloseResources(closers ...io.Closer) error {
	errs := make(chan error, len(closers))
	var wg sync.WaitGroup
	for _, c := range closers {
		wg.Go(func() {
			if err := c.Close(); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)

	var result error
	for err := range errs {
		result = errors.Join(result, err)
	}
	return result
}
