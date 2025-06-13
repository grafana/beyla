package ebpfcommon

import (
	"bytes"
	"context"
	"encoding/binary"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/mariomac/guara/pkg/test"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/ebpf/ringbuf"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/svc"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/v2/pkg/config"
	"github.com/grafana/beyla/v2/pkg/internal/imetrics"
	"github.com/grafana/beyla/v2/pkg/internal/request"
)

const testTimeout = 5 * time.Second

func TestForwardRingbuf_CapacityFull(t *testing.T) {
	// GIVEN a ring buffer forwarder
	ringBuf := replaceTestRingBuf()
	metrics := &metricsReporter{}
	forwardedMessagesQueue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100))
	forwardedMessages := forwardedMessagesQueue.Subscribe()
	fltr := TestPidsFilter{services: map[uint32]svc.Attrs{}}
	fltr.AllowPID(1, 1, &svc.Attrs{UID: svc.UID{Name: "myService"}}, PIDTypeGo)
	go ForwardRingbuf(
		&config.EBPFTracer{BatchLength: 10},
		nil, // the source ring buffer can be null
		&fltr,
		ReadBPFTraceAsSpan,
		slog.With("test", "TestForwardRingbuf_CapacityFull"),
		metrics,
		nil,
	)(context.Background(), forwardedMessagesQueue)

	// WHEN it starts receiving trace events
	var get = [7]byte{'G', 'E', 'T', 0, 0, 0, 0}
	for i := 0; i < 20; i++ {
		t := HTTPRequestTrace{Type: 1, Method: get, ContentLength: int64(i)}
		t.Pid.HostPid = 1
		ringBuf.events <- t
	}

	// THEN the RingBuf reader forwards them in batches
	batch := testutil.ReadChannel(t, forwardedMessages, testTimeout)
	require.Len(t, batch, 10)
	for i := range batch {
		assert.Equal(t, request.Span{Type: 1, Method: "GET", ContentLength: int64(i), Service: svc.Attrs{UID: svc.UID{Name: "myService"}}, Pid: request.PidInfo{HostPID: 1}}, batch[i])
	}

	batch = testutil.ReadChannel(t, forwardedMessages, testTimeout)
	require.Len(t, batch, 10)
	for i := range batch {
		assert.Equal(t, request.Span{Type: 1, Method: "GET", ContentLength: int64(10 + i), Service: svc.Attrs{UID: svc.UID{Name: "myService"}}, Pid: request.PidInfo{HostPID: 1}}, batch[i])
	}
	// AND metrics are properly updated
	assert.Equal(t, 2, metrics.flushes)
	assert.Equal(t, 20, metrics.flushedLen)

	// AND does not forward any extra message if no more elements are in the ring buffer
	select {
	case ev := <-forwardedMessages:
		assert.Failf(t, "unexpected messages in the forwarding channel", "%+v", ev)
	default:
		// OK!
	}
}

func TestForwardRingbuf_Deadline(t *testing.T) {
	// GIVEN a ring buffer forwarder
	ringBuf := replaceTestRingBuf()

	metrics := &metricsReporter{}
	forwardedMessagesQueue := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100))
	forwardedMessages := forwardedMessagesQueue.Subscribe()
	fltr := TestPidsFilter{services: map[uint32]svc.Attrs{}}
	fltr.AllowPID(1, 1, &svc.Attrs{UID: svc.UID{Name: "myService"}}, PIDTypeGo)
	go ForwardRingbuf(
		&config.EBPFTracer{BatchLength: 10, BatchTimeout: 20 * time.Millisecond},
		nil,   // the source ring buffer can be null
		&fltr, // change fltr to a pointer
		ReadBPFTraceAsSpan,
		slog.With("test", "TestForwardRingbuf_Deadline"),
		metrics,
	)(context.Background(), forwardedMessagesQueue)

	// WHEN it receives, after a timeout, less events than its internal buffer
	var get = [7]byte{'G', 'E', 'T', 0, 0, 0, 0}
	for i := 0; i < 7; i++ {
		t := HTTPRequestTrace{Type: 1, Method: get, ContentLength: int64(i)}
		t.Pid.HostPid = 1

		ringBuf.events <- t
	}

	// THEN the RingBuf reader forwards them in a smaller batch
	batch := testutil.ReadChannel(t, forwardedMessages, testTimeout)
	for len(batch) < 7 {
		batch = append(batch, testutil.ReadChannel(t, forwardedMessages, testTimeout)...)
	}
	require.Len(t, batch, 7)
	for i := range batch {
		assert.Equal(t, request.Span{Type: 1, Method: "GET", ContentLength: int64(i), Service: svc.Attrs{UID: svc.UID{Name: "myService"}}, Pid: request.PidInfo{HostPID: 1}}, batch[i])
	}

	// AND metrics are properly updated
	assert.Equal(t, 1, metrics.flushes)
	assert.Equal(t, 7, metrics.flushedLen)
}

func TestForwardRingbuf_Close(t *testing.T) {
	// GIVEN a ring buffer forwarder
	ringBuf := replaceTestRingBuf()

	metrics := &metricsReporter{}
	closable := closableObject{}
	go ForwardRingbuf(
		&config.EBPFTracer{BatchLength: 10},
		nil, // the source ring buffer can be null
		(&IdentityPidsFilter{}),
		ReadBPFTraceAsSpan,
		slog.With("test", "TestForwardRingbuf_Close"),
		metrics,
		&closable,
	)(context.Background(), msg.NewQueue[[]request.Span](msg.ChannelBufferLen(100)))

	assert.False(t, ringBuf.explicitClose.Load())
	assert.False(t, closable.closed)

	// WHEN the ring buffer is closed
	close(ringBuf.closeCh)

	// THEN the ring buffer and the passed io.Closer elements have been explicitly closed
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		assert.True(t, ringBuf.explicitClose.Load())
	})
	assert.True(t, closable.closed)

	// AND metrics haven't been updated
	assert.Equal(t, 0, metrics.flushes)
	assert.Equal(t, 0, metrics.flushedLen)
}

// replaces the original ring buffer factory by a fake ring buffer creator and returns it
func replaceTestRingBuf() *fakeRingBufReader {
	rb := fakeRingBufReader{events: make(chan HTTPRequestTrace, 100), closeCh: make(chan struct{})}
	readerFactory = func(_ *ebpf.Map) (ringBufReader, error) {
		return &rb, nil
	}
	return &rb
}

type fakeRingBufReader struct {
	events        chan HTTPRequestTrace
	closeCh       chan struct{}
	explicitClose atomic.Bool
}

func (f *fakeRingBufReader) Close() error {
	f.explicitClose.Store(true)
	close(f.events)
	return nil
}

func (f *fakeRingBufReader) Read() (ringbuf.Record, error) {
	record := ringbuf.Record{}

	err := f.ReadInto(&record)

	return record, err
}

func (f *fakeRingBufReader) ReadInto(record *ringbuf.Record) error {
	select {
	case traceEvent := <-f.events:
		binaryRecord := bytes.Buffer{}
		if err := binary.Write(&binaryRecord, binary.LittleEndian, traceEvent); err != nil {
			return err
		}
		record.RawSample = binaryRecord.Bytes()
		return nil
	case <-f.closeCh:
		return ringbuf.ErrClosed
	}
}

type closableObject struct {
	closed bool
}

func (c *closableObject) Close() error {
	c.closed = true
	return nil
}

type metricsReporter struct {
	imetrics.NoopReporter
	flushes    int
	flushedLen int
}

func (m *metricsReporter) TracerFlush(length int) {
	m.flushes++
	m.flushedLen += length
}

type TestPidsFilter struct {
	services map[uint32]svc.Attrs
}

func (pf *TestPidsFilter) AllowPID(p uint32, _ uint32, s *svc.Attrs, _ PIDType) {
	pf.services[p] = *s
}

func (pf *TestPidsFilter) BlockPID(p uint32, _ uint32) {
	delete(pf.services, p)
}

func (pf *TestPidsFilter) ValidPID(_ uint32, _ uint32, _ PIDType) bool {
	return true
}

func (pf *TestPidsFilter) CurrentPIDs(_ PIDType) map[uint32]map[uint32]svc.Attrs {
	return nil
}

func (pf *TestPidsFilter) Filter(inputSpans []request.Span) []request.Span {
	for i := range inputSpans {
		s := &inputSpans[i]
		s.Service = pf.services[s.Pid.HostPID]
	}
	return inputSpans
}
