package ebpfcommon

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/ebpf-autoinstrument/pkg/testutil"

	"golang.org/x/exp/slog"

	"github.com/cilium/ebpf"

	"github.com/cilium/ebpf/ringbuf"
)

const testTimeout = 5 * time.Second

func TestForwardRingbuf_CapacityFull(t *testing.T) {
	// GIVEN a ring buffer forwarder
	ringBuf, restore := replaceTestRingBuf()
	defer restore()
	forwardedMessages := make(chan []HTTPRequestTrace, 100)
	go ForwardRingbuf(
		&TracerConfig{BatchLength: 10},
		slog.With("test", "TestForwardRingbuf_CapacityFull"),
		nil, // the source ring buffer can be null
		nil,
	)(context.Background(), forwardedMessages)

	// WHEN it starts receiving trace events
	var get = [6]byte{'G', 'E', 'T', 0, 0, 0}
	for i := 0; i < 20; i++ {
		ringBuf.events <- HTTPRequestTrace{Type: 1, Method: get, ContentLength: int64(i)}
	}

	// THEN the RingBuf reader forwards them in batches
	batch := testutil.ReadChannel(t, forwardedMessages, testTimeout)
	require.Len(t, batch, 10)
	for i := range batch {
		assert.Equal(t, HTTPRequestTrace{Type: 1, Method: get, ContentLength: int64(i)}, batch[i])
	}

	batch = testutil.ReadChannel(t, forwardedMessages, testTimeout)
	require.Len(t, batch, 10)
	for i := range batch {
		assert.Equal(t, HTTPRequestTrace{Type: 1, Method: get, ContentLength: int64(10 + i)}, batch[i])
	}

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
	ringBuf, restore := replaceTestRingBuf()
	defer restore()

	forwardedMessages := make(chan []HTTPRequestTrace, 100)
	go ForwardRingbuf(
		&TracerConfig{BatchLength: 10, BatchTimeout: 20 * time.Millisecond},
		slog.With("test", "TestForwardRingbuf_Deadline"),
		nil, // the source ring buffer can be null
		nil,
	)(context.Background(), forwardedMessages)

	// WHEN it receives, after a timeout, less events than its internal buffer
	var get = [6]byte{'G', 'E', 'T', 0, 0, 0}
	for i := 0; i < 7; i++ {
		ringBuf.events <- HTTPRequestTrace{Type: 1, Method: get, ContentLength: int64(i)}
	}

	// THEN the RingBuf reader forwards them in a smaller batch
	batch := testutil.ReadChannel(t, forwardedMessages, testTimeout)
	for len(batch) < 7 {
		batch = append(batch, testutil.ReadChannel(t, forwardedMessages, testTimeout)...)
	}
	require.Len(t, batch, 7)
	for i := range batch {
		assert.Equal(t, HTTPRequestTrace{Type: 1, Method: get, ContentLength: int64(i)}, batch[i])
	}
}

func TestForwardRingbuf_Close(t *testing.T) {
	// GIVEN a ring buffer forwarder
	ringBuf, restore := replaceTestRingBuf()
	defer restore()

	closable := closableObject{}
	go ForwardRingbuf(
		&TracerConfig{BatchLength: 10},
		slog.With("test", "TestForwardRingbuf_Close"),
		nil, // the source ring buffer can be null
		nil,
		&closable,
	)(context.Background(), make(chan []HTTPRequestTrace, 100))

	assert.False(t, ringBuf.explicitClose)
	assert.False(t, closable.closed)

	// WHEN the ring buffer is closed
	close(ringBuf.closeCh)

	// THEN the ring buffer and the passed io.Closer elements have been explicitly closed
	test.Eventually(t, testTimeout, func(t require.TestingT) {
		assert.True(t, ringBuf.explicitClose)
	})
	assert.True(t, closable.closed)
}

// replaces the original ring buffer factory by a fake ring buffer creator and returns it,
// along with a function to invoke deferred to restore the real ring buffer factory
func replaceTestRingBuf() (ringBuf *fakeRingBufReader, restorer func()) {
	rb := fakeRingBufReader{events: make(chan HTTPRequestTrace, 100), closeCh: make(chan struct{})}
	oldReaderFactory := readerFactory
	readerFactory = func(_ *ebpf.Map) (ringBufReader, error) {
		return &rb, nil
	}
	return &rb, func() {
		readerFactory = oldReaderFactory
	}
}

type fakeRingBufReader struct {
	events        chan HTTPRequestTrace
	closeCh       chan struct{}
	explicitClose bool
}

func (f *fakeRingBufReader) Close() error {
	f.explicitClose = true
	close(f.events)
	return nil
}

func (f *fakeRingBufReader) Read() (ringbuf.Record, error) {
	select {
	case traceEvent := <-f.events:
		binaryRecord := bytes.Buffer{}
		if err := binary.Write(&binaryRecord, binary.LittleEndian, traceEvent); err != nil {
			return ringbuf.Record{}, err
		}
		return ringbuf.Record{RawSample: binaryRecord.Bytes()}, nil
	case <-f.closeCh:
		return ringbuf.Record{}, ringbuf.ErrClosed
	}
}

type closableObject struct {
	closed bool
}

func (c *closableObject) Close() error {
	c.closed = true
	return nil
}
