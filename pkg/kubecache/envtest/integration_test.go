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
	"google.golang.org/protobuf/types/known/timestamppb"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/grafana/beyla/v2/pkg/internal/testutil"
	"github.com/grafana/beyla/v2/pkg/kubecache"
	"github.com/grafana/beyla/v2/pkg/kubecache/informer"
	"github.com/grafana/beyla/v2/pkg/kubecache/meta"
	"github.com/grafana/beyla/v2/pkg/kubecache/service"
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
		svcClient.Start(ctx, t, nil)
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
	go stall15.Start(ctx, t, nil)
	go never1.Start(ctx, t, nil)
	go stall5.Start(ctx, t, nil)
	go never2.Start(ctx, t, nil)
	go stall10.Start(ctx, t, nil)
	go never3.Start(ctx, t, nil)

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
	go func() { test.Eventually(t, timeout, func(t require.TestingT) { cl1.Start(ctx, t, nil) }) }()
	go func() { test.Eventually(t, timeout, func(t require.TestingT) { cl2.Start(ctx, t, nil) }) }()
	go func() { test.Eventually(t, timeout, func(t require.TestingT) { cl3.Start(ctx, t, nil) }) }()

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
		svcClient.Start(ctx, t, nil)
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

func TestResultsSortedByTimestamp(t *testing.T) {
	// this test runs better if runs within the whole test suite
	svcClient := serviceClient{
		Address:  fmt.Sprintf("127.0.0.1:%d", freePort),
		Messages: make(chan *informer.Event, 10),
	}
	var deployTwoExtraPods = func() {
		require.NoError(t, k8sClient.Create(ctx, &corev1.Service{
			ObjectMeta: v1.ObjectMeta{Name: "service1-test-result-sorted", Namespace: "default"},
			Spec: corev1.ServiceSpec{
				Ports:     []corev1.ServicePort{{Name: "foo", Port: 8080}},
				ClusterIP: "10.0.0.123", ClusterIPs: []string{"10.0.0.123"},
			},
		}))
		require.NoError(t, k8sClient.Create(ctx, &corev1.Pod{
			ObjectMeta: v1.ObjectMeta{Name: "test-result-sorted-pod", Namespace: "default"},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "test-container", Image: "nginx"}}},
			Status:     corev1.PodStatus{PodIP: "10.0.0.124"},
		}))
	}

	prevTS := time.Time{}
	// should get all the messages before the sync_finished ordered by timestamp
	for {
		evnt := testutil.ReadChannel(t, svcClient.Messages, timeout)
		if evnt.Type == informer.EventType_SYNC_FINISHED {
			break
		}
		// once we know that the synchronization is started, we deploy to extra pods expecting that
		// the update is never received
		if prevTS.IsZero() {
			deployTwoExtraPods()
		}
		evntTS := evnt.Resource.StatusTime.AsTime()
		require.LessOrEqual(t, prevTS, evntTS)
		prevTS = evntTS
	}
	// should get two extra pods after the sync signal
	evnt := testutil.ReadChannel(t, svcClient.Messages, timeout)
	assert.Equal(t, "service1-test-result-sorted", evnt.Resource.Name)
	evnt = testutil.ReadChannel(t, svcClient.Messages, timeout)
	assert.Equal(t, "test-result-sorted-pod", evnt.Resource.Name)
}

// TODO: slow test: try with testing/synctest when it becomes stable (experimental did not work)
// or try to override the testing K8s API to be able to override the creation timestamps
// (it does not work by explicitly setting the creation timestamp in the objectMeta)
func TestFilterByTimestamp(t *testing.T) {
	svcClient := serviceClient{
		Address:  fmt.Sprintf("127.0.0.1:%d", freePort),
		Messages: make(chan *informer.Event, 10),
	}

	// starting test at "now + 1s" to discard any previously created element
	time.Sleep(time.Second)
	discardEventsBefore := timestamppb.New(time.Now())

	// filtering any event before this test
	require.NoError(t, k8sClient.Create(ctx, &corev1.Service{
		ObjectMeta: v1.ObjectMeta{Name: "service1-filter-by-ts", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Ports:     []corev1.ServicePort{{Name: "foo", Port: 8080}},
			ClusterIP: "10.0.0.125", ClusterIPs: []string{"10.0.0.125"},
		},
	}))
	// delaying 1s to force this pod being returned after the previous service
	time.Sleep(time.Second)
	require.NoError(t, k8sClient.Create(ctx, &corev1.Pod{
		ObjectMeta: v1.ObjectMeta{Name: "pod-filter-by-ts", Namespace: "default"},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "test-container", Image: "nginx"}}},
		Status:     corev1.PodStatus{PodIP: "10.0.0.126"},
	}))
	test.Eventually(t, timeout, func(t require.TestingT) {
		svcClient.Start(ctx, t, discardEventsBefore)
	})

	evnt := testutil.ReadChannel(t, svcClient.Messages, timeout)
	assert.Equal(t, "service1-filter-by-ts", evnt.Resource.Name)
	evnt = testutil.ReadChannel(t, svcClient.Messages, timeout)
	assert.Equal(t, "pod-filter-by-ts", evnt.Resource.Name)
	evnt = testutil.ReadChannel(t, svcClient.Messages, timeout)
	assert.Equal(t, informer.EventType_SYNC_FINISHED, evnt.Type)

	require.NoError(t, k8sClient.Create(ctx, &corev1.Service{
		ObjectMeta: v1.ObjectMeta{Name: "more-filter-by-ts", Namespace: "default"},
		Spec: corev1.ServiceSpec{
			Ports:     []corev1.ServicePort{{Name: "foo", Port: 8080}},
			ClusterIP: "10.0.0.127", ClusterIPs: []string{"10.0.0.127"},
		},
	}))
	evnt = testutil.ReadChannel(t, svcClient.Messages, timeout)
	assert.Equal(t, "more-filter-by-ts", evnt.Resource.Name)
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

func (sc *serviceClient) Start(ctx context.Context, t require.TestingT, fromTS *timestamppb.Timestamp) {
	conn, err := grpc.NewClient(sc.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	eventsClient := informer.NewEventStreamServiceClient(conn)

	// Subscribe to the event stream.
	stream, err := eventsClient.Subscribe(ctx, &informer.SubscribeMessage{FromTimestamp: fromTS})
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
				fmt.Printf("%+v\n", event)
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
