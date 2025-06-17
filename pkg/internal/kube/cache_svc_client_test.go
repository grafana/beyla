package kube

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/testutil"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/kubecache/informer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/grafana/beyla/v2/pkg/kubecache/meta"
)

const timeout = 5 * time.Second

func TestClientForwardsLastTimestamp(t *testing.T) {
	// PREREQUISITE: a K8s metadata cache service that forwards some events
	fcs := startFakeCacheService(t)
	itemTime := int64(1234567890)
	fcs.serverResponses <- &informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name: "svc-1", Namespace: "default",
			StatusTimeEpoch: itemTime - 1,
		},
	}
	fcs.serverResponses <- &informer.Event{
		Type: informer.EventType_CREATED,
		Resource: &informer.ObjectMeta{
			Name: "svc-1", Namespace: "default",
			StatusTimeEpoch: itemTime,
		},
	}
	fcs.serverResponses <- &informer.Event{
		Type: informer.EventType_SYNC_FINISHED,
	}

	// GIVEN a K8s cache client
	svc := cacheSvcClient{
		address:       fmt.Sprintf("127.0.0.1:%d", fcs.port),
		BaseNotifier:  meta.NewBaseNotifier(klog()),
		syncTimeout:   timeout,
		reconnectTime: 10 * time.Millisecond,
	}

	// WHEN it is subscribed to a cache service for the first time
	svc.Start(t.Context())
	svc.Subscribe(dummySubscriber{})

	// THEN the client sends a first subscription message with no timestamp
	firstSubscribe := testutil.ReadChannel(t, fcs.clientMessages, timeout)
	assert.Zero(t, firstSubscribe.FromTimestampEpoch)

	// AND WHEN the connection is interrupted then restored
	fcs.Restart()
	fcs.serverResponses <- &informer.Event{
		Type: informer.EventType_SYNC_FINISHED,
	}

	// THEN the client sends another subscription message, with the timestamp of the last received event
	secondSubscribe := testutil.ReadChannel(t, fcs.clientMessages, timeout)
	assert.Equal(t, itemTime, secondSubscribe.FromTimestampEpoch)
}

// cacheSvcClient requires a subscriber to start processing the events, so we provide a dummy here
type dummySubscriber struct{}

func (f dummySubscriber) ID() string                 { return "fake-subscriber" }
func (f dummySubscriber) On(_ *informer.Event) error { return nil }

// fakeCacheService accepts gRPC requests from the client and records the received messages
// also lets explicit which events forward to the client
type fakeCacheService struct {
	informer.UnimplementedEventStreamServiceServer
	port     int
	err      atomic.Pointer[error]
	server   *grpc.Server
	listener net.Listener

	clientMessages  chan *informer.SubscribeMessage
	serverResponses chan *informer.Event
}

func startFakeCacheService(t *testing.T) *fakeCacheService {
	port, err := test.FreeTCPPort()
	require.NoError(t, err)
	fcs := &fakeCacheService{
		port:            port,
		clientMessages:  make(chan *informer.SubscribeMessage, 10),
		serverResponses: make(chan *informer.Event, 10),
	}
	t.Cleanup(func() { fcs.server.Stop() })
	fcs.Start()
	return fcs
}

func (fcs *fakeCacheService) Start() {
	fcs.server = grpc.NewServer()
	informer.RegisterEventStreamServiceServer(fcs.server, fcs)

	var err error
	fcs.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", fcs.port))
	if err != nil {
		err := fmt.Errorf("starting TCP connection: %w", err)
		fcs.err.Store(&err)
		return
	}
	go func() {
		if err := fcs.server.Serve(fcs.listener); err != nil {
			err = fmt.Errorf("grpc.Serve returned: %w", err)
			fcs.err.Store(&err)
		}
	}()
}

func (fcs *fakeCacheService) Restart() {
	fcs.server.Stop()
	fcs.listener.Close()
	fcs.Start()
}

func (fcs *fakeCacheService) Err() error {
	if perr := fcs.err.Load(); perr != nil {
		return *perr
	}
	return nil
}

func (fcs *fakeCacheService) Subscribe(message *informer.SubscribeMessage, g grpc.ServerStreamingServer[informer.Event]) error {
	fcs.clientMessages <- message
	for msg := range fcs.serverResponses {
		if err := g.Send(msg); err != nil {
			return fmt.Errorf("sending response to client: %w", err)
		}
	}
	return nil
}
