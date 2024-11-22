package envtest

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/grafana/beyla/pkg/kubecache"
	"github.com/grafana/beyla/pkg/kubecache/informer"
	"github.com/grafana/beyla/pkg/kubecache/meta"
	"github.com/grafana/beyla/pkg/kubecache/service"
)

var (
	ctx       context.Context
	k8sClient client.Client
	testEnv   *envtest.Environment

	kubeAPIIface kubernetes.Interface
)

const timeout = 10 * time.Second

var freePort int

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug})))
	var cancel context.CancelFunc
	ctx, cancel = context.WithCancel(context.TODO())

	// setup global testEnv instances and client classes. This will create a "fake kubernetes" API
	// to integrate it within our informers' cache for unit testing without requiring
	// spinning up a Kind K8s cluster
	testEnv = &envtest.Environment{}
	cfg, err := testEnv.Start()
	if err != nil {
		slog.Error("starting test environment", "error", err)
		os.Exit(1)
	}
	k8sManager, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme.Scheme})
	if err != nil {
		slog.Error("creating manager", "error", err)
		os.Exit(1)
	}
	config := k8sManager.GetConfig()
	kubeAPIIface, err = kubernetes.NewForConfig(config)
	if err != nil {
		slog.Error("creating kube API client", "error", err)
		os.Exit(1)
	}
	k8sClient, err = client.New(cfg, client.Options{Scheme: scheme.Scheme})
	if err != nil {
		slog.Error("creating K8s manager client", "error", err)
		os.Exit(1)
	}
	freePort, err = test.FreeTCPPort()
	if err != nil {
		slog.Error("getting a free TCP port", "error", err)
		os.Exit(1)
	}
	go func() {
		if err := k8sManager.Start(ctx); err != nil {
			slog.Error("starting manager", "error", err)
			os.Exit(1)
		}
	}()
	defer func() {
		cancel()
		if err := testEnv.Stop(); err != nil {
			slog.Error("stopping test environment", "error", err)
		}
	}()

	// Create and start informers client cache
	iConfig := kubecache.DefaultConfig
	iConfig.Port = freePort
	svc := service.InformersCache{Config: &iConfig, SendTimeout: 150 * time.Millisecond}
	go func() {
		if err := svc.Run(ctx,
			meta.WithResyncPeriod(iConfig.InformerResyncPeriod),
			meta.WithKubeClient(kubeAPIIface),
		); err != nil {
			slog.Error("running service", "error", err)
			os.Exit(1)
		}
	}()

	m.Run()
}

func TestAPIs(t *testing.T) {
	svcClient := serviceClient{
		Address:  fmt.Sprintf("127.0.0.1:%d", freePort),
		Messages: make(chan *informer.Event, 10),
	}
	test.Eventually(t, timeout, func(t require.TestingT) {
		svcClient.Start(ctx, t)
	})

	// wait for the service to have sent the initial snapshot of entities
	// (at the end, will send the "SYNC_FINISHED" event)
	test.Eventually(t, timeout, func(t require.TestingT) {
		event := ReadChannel(t, svcClient.Messages, timeout)
		require.Equal(t, informer.EventType_SYNC_FINISHED, event.Type)
	})

	// WHEN a pod is created
	require.NoError(t, k8sClient.Create(ctx, &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{
			Name:      "second-pod",
			Namespace: "default",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "test-container", Image: "nginx"},
			},
		},
	}))

	// THEN the informer cache sends the notification to its subscriptors
	test.Eventually(t, timeout, func(t require.TestingT) {
		event := ReadChannel(t, svcClient.Messages, timeout)
		assert.Equal(t, informer.EventType_CREATED, event.Type)
		require.Equal(t, "second-pod", event.Resource.Name)
		assert.Equal(t, "Pod", event.Resource.Kind)
		assert.Equal(t, "default", event.Resource.Namespace)
		// not checking some pod fields as they are not set by the testenv library
		// They must be checked in integration tests
		assert.NotEmpty(t, event.Resource.Pod.Uid)
		assert.NotEmpty(t, event.Resource.Pod.StartTimeStr)
	})
}

func TestBlockedClients(t *testing.T) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// a varied number of cache clients connect concurrently. Some of them are blocked
	// after a while, and they don't release the connection
	addr := fmt.Sprintf("127.0.0.1:%d", freePort)
	never1 := &serviceClient{Address: addr, stallAfterMessages: 1000000}
	never2 := &serviceClient{Address: addr, stallAfterMessages: 1000000}
	never3 := &serviceClient{Address: addr, stallAfterMessages: 1000000}
	stall5 := &serviceClient{Address: addr, stallAfterMessages: 5}
	stall10 := &serviceClient{Address: addr, stallAfterMessages: 10}
	stall15 := &serviceClient{Address: addr, stallAfterMessages: 15}
	go stall15.Start(ctx, t)
	go never1.Start(ctx, t)
	go stall5.Start(ctx, t)
	go never2.Start(ctx, t)
	go stall10.Start(ctx, t)
	go never3.Start(ctx, t)

	// generating a large number of notifications until the gRPC buffer of the
	// server-to-client connections is full, so the "Send" operation is blocked
	allSent := make(chan struct{})
	const createdPods = 1500
	go func() {
		for n := 0; n < createdPods; n++ {
			require.NoError(t, k8sClient.Create(ctx, &corev1.Pod{
				ObjectMeta: v1.ObjectMeta{
					Name:      fmt.Sprintf("pod-%02d", n),
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{Name: "test-container", Image: "nginx"},
					},
				},
			}))
		}
		close(allSent)
	}()

	test.Eventually(t, timeout, func(t require.TestingT) {
		// the clients that got stalled, just received the expected number of messages
		// before they got blocked
		require.EqualValues(t, int32(5), stall5.readMessages.Load())
		require.EqualValues(t, int32(10), stall10.readMessages.Load())
		require.EqualValues(t, int32(15), stall15.readMessages.Load())

		// but that did not block the rest of clients, which got all the expected messages
		require.GreaterOrEqual(t, never1.readMessages.Load(), int32(createdPods))
		require.GreaterOrEqual(t, never2.readMessages.Load(), int32(createdPods))
		require.GreaterOrEqual(t, never3.readMessages.Load(), int32(createdPods))

	})

	// we don't exit until all the pods have been created, to avoid failing the
	// tests because the client.Create operation fails due to premature context cancellation
	ReadChannel(t, allSent, timeout)
}

// makes sure that a new cache server won't forward the sync data to the clients until
// it effectively has synced everything
func TestAsynchronousStartup(t *testing.T) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// generating some contents to force a new Beyla Cache service to take a while
	// to synchronize during initialization
	const createdPods = 20
	for n := 0; n < createdPods; n++ {
		require.NoError(t, k8sClient.Create(ctx, &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{
				Name:      fmt.Sprintf("async-pod-%02d", n),
				Namespace: "default",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "test-container", Image: "nginx"},
				},
			},
		}))
	}

	// creating a new Beyla cache service instance that will start synchronizing with
	// the previously generated amount of data (also from previous tests)
	newFreePort, err := test.FreeTCPPort()
	require.NoError(t, err)

	// create few clients that start trying to connect and sync
	// even before the new cache service starts
	addr := fmt.Sprintf("127.0.0.1:%d", newFreePort)
	cl1 := serviceClient{Address: addr}
	cl2 := serviceClient{Address: addr}
	cl3 := serviceClient{Address: addr}
	go func() { test.Eventually(t, timeout, func(t require.TestingT) { cl1.Start(ctx, t) }) }()
	go func() { test.Eventually(t, timeout, func(t require.TestingT) { cl2.Start(ctx, t) }) }()
	go func() { test.Eventually(t, timeout, func(t require.TestingT) { cl3.Start(ctx, t) }) }()

	iConfig := kubecache.DefaultConfig
	iConfig.Port = newFreePort
	svc := service.InformersCache{Config: &iConfig, SendTimeout: time.Second}
	go func() {
		require.NoError(t, svc.Run(ctx,
			meta.WithResyncPeriod(iConfig.InformerResyncPeriod),
			meta.WithKubeClient(kubeAPIIface),
		))
	}()

	// The clients should have received the Sync complete signal even if they
	// connected to the cache service before it was fully synchronized
	test.Eventually(t, timeout, func(t require.TestingT) {
		require.NotZero(t, cl1.syncSignalOnMessage.Load())
		require.NotZero(t, cl2.syncSignalOnMessage.Load())
		require.NotZero(t, cl3.syncSignalOnMessage.Load())
	})
	assert.LessOrEqual(t, int32(createdPods), cl1.syncSignalOnMessage.Load())
	assert.LessOrEqual(t, int32(createdPods), cl2.syncSignalOnMessage.Load())
	assert.LessOrEqual(t, int32(createdPods), cl3.syncSignalOnMessage.Load())
}

func TestIgnoreHeadlessServices(t *testing.T) {
	svcClient := serviceClient{
		Address:  fmt.Sprintf("127.0.0.1:%d", freePort),
		Messages: make(chan *informer.Event, 10),
	}
	test.Eventually(t, timeout, func(t require.TestingT) {
		svcClient.Start(ctx, t)
	})
	// wait for the service to have sent the initial snapshot of entities
	// (at the end, will send the "SYNC_FINISHED" event)
	test.Eventually(t, timeout, func(t require.TestingT) {
		event := ReadChannel(t, svcClient.Messages, timeout)
		require.Equal(t, informer.EventType_SYNC_FINISHED, event.Type)
	})

	// WHEN services are created
	require.NoError(t, k8sClient.Create(ctx, &corev1.Service{
		ObjectMeta: v1.ObjectMeta{Name: "service1", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Ports:     []corev1.ServicePort{{Name: "foo", Port: 8080}},
			ClusterIP: "10.0.0.101", ClusterIPs: []string{"10.0.0.101"},
		},
	}))
	require.NoError(t, k8sClient.Create(ctx, &corev1.Service{
		ObjectMeta: v1.ObjectMeta{Name: "headless", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Ports:     []corev1.ServicePort{{Name: "foo", Port: 8080}},
			ClusterIP: "None",
		},
	}))
	require.NoError(t, k8sClient.Create(ctx, &corev1.Service{
		ObjectMeta: v1.ObjectMeta{Name: "service2", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Ports:     []corev1.ServicePort{{Name: "foo", Port: 8080}},
			ClusterIP: "10.0.0.102", ClusterIPs: []string{"10.0.0.102"},
		},
	}))

	// THEN the informer cache receives the services with an IP
	// AND ignores headless services (without ClusterIP)
	event := ReadChannel(t, svcClient.Messages, timeout)
	require.NotNil(t, event.Resource)
	assert.Equal(t, "service1", event.Resource.Name)
	assert.NotEmpty(t, event.Resource.Ips)

	event = ReadChannel(t, svcClient.Messages, timeout)
	require.NotNil(t, event.Resource)
	assert.Equal(t, "service2", event.Resource.Name)
	assert.NotEmpty(t, event.Resource.Ips)

	select {
	case event := <-svcClient.Messages:
		assert.Failf(t, "did not expect more informer updates. Got %s", event.String())
	default:
		// ok!
	}
}

func ReadChannel[T any](t require.TestingT, inCh <-chan T, timeout time.Duration) T {
	var item T
	select {
	case item = <-inCh:
		return item
	case <-time.After(timeout):
		t.Errorf("timeout (%s) while waiting for event in input channel", timeout)
		t.FailNow()
	}
	return item
}

type serviceClient struct {
	// Address of the cache service
	Address string
	// Messages to be forwarded on read. If nil, the client won't forward anything
	Messages chan *informer.Event
	// counter of read messages
	readMessages atomic.Int32
	// if != 0, the client will be blocked when the count of read messages reach stallAfterMessages
	stallAfterMessages int32
	// stores at which message number the signal is synced
	syncSignalOnMessage atomic.Int32
}

func (sc *serviceClient) Start(ctx context.Context, t require.TestingT) {
	conn, err := grpc.NewClient(sc.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	eventsClient := informer.NewEventStreamServiceClient(conn)

	// Subscribe to the event stream.
	stream, err := eventsClient.Subscribe(ctx, &informer.SubscribeMessage{})
	require.NoError(t, err)

	// Receive and print messages.
	go func() {
		defer conn.Close()
		for {
			if sc.stallAfterMessages != 0 && sc.stallAfterMessages == sc.readMessages.Load() {
				// just block without doing any connection activity
				// nor closing/releasing the connection
				<-stream.Context().Done()
				return
			}
			event, err := stream.Recv()
			if err != nil {
				slog.Error("receiving message at client side", "error", err)
				break
			}
			sc.readMessages.Add(1)
			if sc.Messages != nil {
				sc.Messages <- event
			}
			if event.Type == informer.EventType_SYNC_FINISHED {
				if sc.syncSignalOnMessage.Load() != 0 {
					slog.Error(fmt.Sprintf("client %s: can't receive two signal sync messages! (received at %d and %d)",
						conn.GetState().String(), sc.syncSignalOnMessage.Load(), sc.readMessages.Load()))
					return
				}
				sc.syncSignalOnMessage.Store(sc.readMessages.Load())
			}
		}
	}()
}
