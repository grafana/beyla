package ebpfcommon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

// ringBufReader interface extracts the used methods from ringbuf.Reader for proper
// dependency injection during tests
type ringBufReader interface {
	io.Closer
	Read() (ringbuf.Record, error)
}

// readerFactory instantiates a ringBufReader from a ring buffer. In unit tests, we can
// replace this function by a mock/dummy.
var readerFactory = func(rb *ebpf.Map) (ringBufReader, error) {
	return ringbuf.NewReader(rb)
}

type ringBufForwarder[T any] struct {
	service svc.ID

	cfg        *TracerConfig
	logger     *slog.Logger
	ringbuffer *ebpf.Map
	closers    []io.Closer
	spans      []request.Span
	spansLen   int
	access     sync.Mutex
	ticker     *time.Ticker
	reader     func(*ringbuf.Record) (request.Span, bool, error)
	metrics    imetrics.Reporter
}

// ForwardRingbuf returns a function reads HTTPRequestTraces from an input ring buffer, accumulates them into an
// internal buffer, and forwards them to an output events channel, previously converted to request.Span
// instances.
func ForwardRingbuf[T any](
	service svc.ID,
	cfg *TracerConfig,
	logger *slog.Logger,
	ringbuffer *ebpf.Map,
	reader func(*ringbuf.Record) (request.Span, bool, error),
	metrics imetrics.Reporter,
	closers ...io.Closer,
) func(context.Context, chan<- []request.Span) {
	rbf := ringBufForwarder[T]{
		service: service, cfg: cfg, logger: logger, ringbuffer: ringbuffer,
		closers: closers, reader: reader, metrics: metrics,
	}
	return rbf.readAndForward
}

func (rbf *ringBufForwarder[T]) readAndForward(ctx context.Context, spansChan chan<- []request.Span) {
	rbf.logger.Debug("start reading and forwarding")
	// BPF will send each measured trace via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating perf reader. Exiting", err)
		return
	}
	rbf.closers = append(rbf.closers, eventsReader)
	defer rbf.closeAllResources()

	rbf.spans = make([]request.Span, rbf.cfg.BatchLength)
	rbf.spansLen = 0

	// If the underlying context is closed, it closes the events reader
	// so the function can exit.
	go rbf.bgListenContextCancelation(ctx, eventsReader)

	// Forwards periodically on timeout, if the batch is not full
	if rbf.cfg.BatchTimeout > 0 {
		rbf.ticker = time.NewTicker(rbf.cfg.BatchTimeout)
		go rbf.bgFlushOnTimeout(spansChan)
	}

	// Main loop:
	// 1. Listen for content in the ring buffer
	// 2. Decode binary data into HTTPRequestTrace instance
	// 3. Accumulate the HTTPRequestTrace into a batch slice
	// 4. When the length of the batch slice reaches cfg.BatchLength,
	//    submit it to the next stage of the pipeline
	for {
		rbf.logger.Debug("starting to read perf buffer")
		record, err := eventsReader.Read()
		rbf.logger.Debug("received event")
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				rbf.logger.Debug("ring buffer is closed")
				return
			}
			rbf.logger.Error("error reading from perf reader", err)
			continue
		}
		rbf.access.Lock()
		s, ignore, err := rbf.reader(&record)
		if err != nil {
			rbf.logger.Error("error parsing perf event", err)
			rbf.access.Unlock()
			continue
		}
		if ignore {
			rbf.access.Unlock()
			continue
		}
		s.ServiceID = rbf.service
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
		rbf.access.Unlock()
	}
}

func (rbf *ringBufForwarder[T]) flushEvents(spansChan chan<- []request.Span) {
	rbf.metrics.TracerFlush(rbf.spansLen)
	spansChan <- rbf.spans[:rbf.spansLen]
	rbf.spans = make([]request.Span, rbf.cfg.BatchLength)
	rbf.spansLen = 0
}

func (rbf *ringBufForwarder[T]) bgFlushOnTimeout(spansChan chan<- []request.Span) {
	for {
		<-rbf.ticker.C
		rbf.access.Lock()
		if rbf.spansLen > 0 {
			rbf.logger.Debug("submitting traces on timeout", "len", rbf.spansLen)
			rbf.flushEvents(spansChan)
		}
		rbf.access.Unlock()
	}
}

func (rbf *ringBufForwarder[T]) bgListenContextCancelation(ctx context.Context, eventsReader ringBufReader) {
	<-ctx.Done()
	rbf.logger.Debug("context is cancelled. Closing events reader")
	_ = eventsReader.Close()
}

func (rbf *ringBufForwarder[T]) closeAllResources() {
	rbf.logger.Debug("closing eBPF resources")
	for _, c := range rbf.closers {
		_ = c.Close()
	}
}
