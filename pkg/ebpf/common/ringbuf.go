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

func ForwardRingbuf(
	cfg *Tracer,
	logger *slog.Logger,
	ringbuffer *ebpf.Map,
	closers ...io.Closer,
) node.StartFuncCtx[[]HTTPRequestTrace] {
	// TODO: make use of context to cancel process
	return func(_ context.Context, eventsChan chan<- []HTTPRequestTrace) {
		// BPF will send each measured trace via Ring Buffer, so we listen for them from the
		// user space.
		eventsReader, err := ringbuf.NewReader(ringbuffer)
		if err != nil {
			logger.Error("creating perf reader. Exiting", err)
			return
		}
		defer func() {
			logger.Debug("closing eBPF resources")
			_ = eventsReader.Close()
			for _, c := range closers {
				_ = c.Close()
			}
		}()

		events := make([]HTTPRequestTrace, cfg.BatchLength)
		ev := 0
		ticker := time.NewTicker(cfg.BatchTimeout)
		access := sync.Mutex{}
		go func() {
			if cfg.BatchTimeout == 0 {
				return
			}
			// submit periodically on timeout, if the batch is not full
			for {
				<-ticker.C
				access.Lock()
				if ev > 0 {
					logger.Debug("submitting traces on timeout", "len", ev)
					eventsChan <- events[:ev]
					events = make([]HTTPRequestTrace, cfg.BatchLength)
					ev = 0
				}
				access.Unlock()
			}
		}()
		for {
			logger.Debug("starting to read perf buffer")
			record, err := eventsReader.Read()
			logger.Debug("received event")
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					logger.Debug("ring buffer is closed")
					return
				}
				logger.Error("error reading from perf reader", err)
				continue
			}

			access.Lock()
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &events[ev])
			if err != nil {
				logger.Error("error parsing perf event", err)
				access.Unlock()
				continue
			}
			ev++
			if ev == cfg.BatchLength {
				logger.Debug("submitting traces after batch is full", "len", ev)
				eventsChan <- events
				events = make([]HTTPRequestTrace, cfg.BatchLength)
				ev = 0
				ticker.Reset(cfg.BatchTimeout)
			}
			access.Unlock()
		}
	}
}
