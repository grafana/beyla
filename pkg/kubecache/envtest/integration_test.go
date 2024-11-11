package envtest

import (
	"context"
	"fmt"
	"log/slog"
	"os"
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
	theClient, err := kubernetes.NewForConfig(config)
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
	svc := service.InformersCache{Config: &iConfig}
	go func() {
		if err := svc.Run(ctx,
			meta.WithResyncPeriod(iConfig.InformerResyncPeriod),
			meta.WithKubeClient(theClient),
		); err != nil {
			slog.Error("running service", "error", err)
			os.Exit(1)
		}
	}()

	m.Run()
}

func TestAPIs(t *testing.T) {
	svcClient := serviceClient{ID: "first-pod", Address: fmt.Sprintf("127.0.0.1:%d", freePort)}
	// client
	require.Eventually(t, func() bool {
		return svcClient.Start(ctx) == nil
	}, timeout, 100*time.Millisecond)

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
	ID       string
	Address  string
	Messages chan *informer.Event
}

func (sc *serviceClient) Start(ctx context.Context) error {
	sc.Messages = make(chan *informer.Event, 10)

	conn, err := grpc.NewClient(sc.Address,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("can't connect client: %w", err)
	}

	eventsClient := informer.NewEventStreamServiceClient(conn)

	// Subscribe to the event stream.
	stream, err := eventsClient.Subscribe(ctx, &informer.SubscribeMessage{})
	if err != nil {
		return fmt.Errorf("subscribing: %w", err)
	}

	// Receive and print messages.
	go func() {
		defer conn.Close()
		for {
			event, err := stream.Recv()
			if err != nil {
				slog.Error("receiving message at client side", "error", err)
				break
			}
			sc.Messages <- event
		}

	}()
	return nil
}
