package ebpfcommon

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/mariomac/pipes/pkg/node"
	"golang.org/x/exp/slog"
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

type ringBufForwarder struct {
	cfg         *TracerConfig
	logger      *slog.Logger
	ringbuffer  *ebpf.Map
	closers     []io.Closer
	events      []HTTPRequestTrace
	evLen       int
	access      sync.Mutex
	ticker      *time.Ticker
	transformer func(*ringbuf.Record) (HTTPRequestTrace, error)
}

// ForwardRingbuf returns a function reads HTTPRequestTraces from an input ring buffer, accumulates them into an
// internal buffer, and forwards them to an output events channel, previously converted to transform.HTTPRequestSpan
// instances
func ForwardRingbuf(
	cfg *TracerConfig,
	logger *slog.Logger,
	ringbuffer *ebpf.Map,
	recordTransformer func(*ringbuf.Record) (HTTPRequestTrace, error),
	closers ...io.Closer,
) node.StartFuncCtx[[]HTTPRequestTrace] {
	rbf := ringBufForwarder{
		cfg: cfg, logger: logger, ringbuffer: ringbuffer, closers: closers, transformer: recordTransformer,
	}
	return rbf.readAndForward
}

func (rbf *ringBufForwarder) readAndForward(ctx context.Context, eventsChan chan<- []HTTPRequestTrace) {
	// BPF will send each measured trace via Ring Buffer, so we listen for them from the
	// user space.
	eventsReader, err := readerFactory(rbf.ringbuffer)
	if err != nil {
		rbf.logger.Error("creating perf reader. Exiting", err)
		return
	}
	rbf.closers = append(rbf.closers, eventsReader)
	defer rbf.closeAllResources()

	rbf.events = make([]HTTPRequestTrace, rbf.cfg.BatchLength)
	rbf.evLen = 0

	// If the underlying context is closed, it closes the events reader
	// so the function can exit.
	go rbf.bgListenContextCancelation(ctx, eventsReader)

	// Forwards periodically on timeout, if the batch is not full
	if rbf.cfg.BatchTimeout > 0 {
		rbf.ticker = time.NewTicker(rbf.cfg.BatchTimeout)
		go rbf.bgFlushOnTimeout(eventsChan)
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
		if rbf.transformer != nil {
			rbf.events[rbf.evLen], err = rbf.transformer(&record)
		} else {
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &rbf.events[rbf.evLen])
		}
		if err != nil {
			rbf.logger.Error("error parsing perf event", err)
			rbf.access.Unlock()
			continue
		}
		rbf.evLen++
		if rbf.evLen == rbf.cfg.BatchLength {
			rbf.logger.Debug("submitting traces after batch is full", "len", rbf.evLen)
			rbf.flushEvents(eventsChan)
			if rbf.ticker != nil {
				rbf.ticker.Reset(rbf.cfg.BatchTimeout)
			}
		}
		rbf.access.Unlock()
	}
}

func (rbf *ringBufForwarder) flushEvents(eventsChan chan<- []HTTPRequestTrace) {
	eventsChan <- rbf.events[:rbf.evLen]
	rbf.events = make([]HTTPRequestTrace, rbf.cfg.BatchLength)
	rbf.evLen = 0
}

func (rbf *ringBufForwarder) bgFlushOnTimeout(eventsChan chan<- []HTTPRequestTrace) {
	for {
		<-rbf.ticker.C
		rbf.access.Lock()
		if rbf.evLen > 0 {
			rbf.logger.Debug("submitting traces on timeout", "len", rbf.evLen)
			rbf.flushEvents(eventsChan)
		}
		rbf.access.Unlock()
	}
}

func (rbf *ringBufForwarder) bgListenContextCancelation(ctx context.Context, eventsReader ringBufReader) {
	<-ctx.Done()
	_ = eventsReader.Close()
}

func (rbf *ringBufForwarder) closeAllResources() {
	rbf.logger.Debug("closing eBPF resources")
	for _, c := range rbf.closers {
		_ = c.Close()
	}
}
