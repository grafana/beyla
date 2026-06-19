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
	metrics imetrics.Reporter
	// lastReadAtUnixNano is updated by the read loop and observed by the periodic flusher.
	lastReadAtUnixNano atomic.Int64
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
		rbf.logger.Error("creating ring buffer reader. Exiting", "error", err)
		return
	}
	// If the underlying context is closed, it closes the objects we have allocated for this bpf program.
	// We wait for the closer goroutine to finish before returning so that callers (e.g. Instrumenter.stop)
	// do not signal completion while eBPF resources are still being torn down.
	var closerDone sync.WaitGroup
	closerDone.Go(func() {
		rbf.bgListenSharedContextCancelation(ctx, closers, eventsReader)
	})
	rbf.readAndForwardInner(ctx, eventsReader, out)
	closerDone.Wait()
}

func (rbf *ringBufForwarder[T]) readAndForward(ctx context.Context, out *msg.Queue[[]T]) {
	rbf.logger.Debug("start reading and forwarding")
	// BPF will send each measured item via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating ring buffer reader. Exiting", "error", err)
		return
	}
	rbf.closers = append(rbf.closers, eventsReader)
	defer rbf.closeAllResources()

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
			if available > 0 && rbf.hasPendingReadIdleSince(time.Now(), flushInterval) {
				err := eventsReader.Flush()
				rbf.logger.Debug("flushing ringbuf", "available_bytes", available, "flush_err", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (rbf *ringBufForwarder[T]) readAndForwardInner(ctx context.Context, eventsReader ringBufReader, out *msg.Queue[[]T]) {
	if rbf.cfg.BatchTimeout > 0 {
		rbf.ticker = time.NewTicker(rbf.cfg.BatchTimeout)
		go rbf.bgFlushOnTimeout(ctx, out)
	}
	go rbf.flushOnAvailableBytes(ctx, eventsReader)

	rbf.items = make([]T, rbf.cfg.BatchLength)
	rbf.itemsLen = 0

	// 2x: one batch for the parser to work on, one for the reader to fill concurrently.
	// Smaller would stall the reader while waiting for the parser to finish.
	poolSize := 2 * rbf.cfg.BatchLength
	records := make([]ringbuf.Record, poolSize)
	freeIdx := make(chan int, poolSize)
	workIdx := make(chan int, poolSize)
	for i := range poolSize {
		freeIdx <- i
	}

	go rbf.parserLoop(ctx, records, freeIdx, workIdx, out)

	rbf.logger.Debug("starting to read ring buffer")
	rbf.readerLoop(ctx, eventsReader, records, freeIdx, workIdx)
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
			rbf.logger.Debug("ring buffer already flushed")
			return true
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
			item, ignore, err := rbf.parse(&records[i])
			freeIdx <- i
			if err != nil {
				rbf.logger.Debug("error parsing ring buffer event", "error", err)
				continue
			}
			if !ignore {
				parsed = append(parsed, item)
			}
		}

		if len(parsed) == 0 {
			continue
		}

		// Lock once to enqueue the whole batch.
		rbf.access.Lock()
		for _, item := range parsed {
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
	// Close the events reader before the eBPF objects so the readerLoop unblocks
	// immediately via ErrClosed, rather than waiting for potentially hundreds of
	// eBPF closers to finish. This trades a small window of data loss (events
	// already in the ring buffer but not yet consumed) for a prompt shutdown.
	rbf.logger.Debug("closing events reader")
	_ = eventsReader.Close()
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
