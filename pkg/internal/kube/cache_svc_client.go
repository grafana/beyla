package kube

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/grafana/beyla/v2/pkg/kubecache/informer"
	"github.com/grafana/beyla/v2/pkg/kubecache/meta"
)

func cslog() *slog.Logger {
	return slog.With("component", "kube.CacheSvcClient")
}

type cacheSvcClient struct {
	meta.BaseNotifier
	address string
	log     *slog.Logger

	lastEventTS            time.Time
	ctx                    context.Context
	syncTimeout            time.Duration
	waitForSubscription    chan struct{}
	waitForSynchronization chan struct{}
	waitForSyncClosed      bool
}

func (sc *cacheSvcClient) ID() string {
	return "kube-metadata-cache-svc-client"
}

func (sc *cacheSvcClient) On(event *informer.Event) error {
	// we can safely assume that server-side events are ordered
	// by timestamp
	sc.lastEventTS = event.Resource.StatusTime.AsTime()
	return nil
}

func (sc *cacheSvcClient) Start(ctx context.Context) {
	sc.log = cslog()
	sc.waitForSubscription = make(chan struct{})
	sc.waitForSynchronization = make(chan struct{})
	sc.ctx = ctx
	// subscribe itself to each message from the cache, to keep track of the
	// message timestamps for a more efficient reconnection
	sc.BaseNotifier.Subscribe(sc)
	go func() {
		select {
		case <-ctx.Done():
			sc.log.Debug("context done, stopping client")
			return
		case <-sc.waitForSubscription:
			sc.log.Debug("subscriptor attached, start connection to K8s cache service")
		}

		for {
			select {
			case <-ctx.Done():
				sc.log.Debug("context done, stopping client")
				return
			default:
				// TODO: reconnection should include a timestamp
				// with the last received event, to avoid unnecessarily
				// receiving the whole metadata snapshot on each reconnection
				err := sc.connect(ctx)
				sc.log.Info("K8s cache service connection lost. Reconnecting...", "error", err)
				// TODO: exponential backoff
				time.Sleep(5 * time.Second)
			}
		}
	}()
}

func (sc *cacheSvcClient) connect(ctx context.Context) error {
	// Set up a connection to the server.
	conn, err := grpc.NewClient(sc.address,
		// TODO: allow configuring the transport credentials
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("did not connect: %w", err)
	}
	defer conn.Close()

	client := informer.NewEventStreamServiceClient(conn)

	// Subscribe to the event stream.
	stream, err := client.Subscribe(ctx, &informer.SubscribeMessage{
		FromTimestamp: timestamppb.New(sc.lastEventTS),
	})
	if err != nil {
		return fmt.Errorf("could not subscribe: %w", err)
	}

	// Receive and print messages.
	for {
		event, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("error receiving message: %w", err)
		}
		// send a notification about the client being synced with the K8s metadata service
		// so Beyla can start processing/decorating the received flows and traces
		if event.GetType() == informer.EventType_SYNC_FINISHED && !sc.waitForSyncClosed {
			close(sc.waitForSynchronization)
			sc.waitForSyncClosed = true
		}
		sc.BaseNotifier.Notify(event)
	}
}

func (sc *cacheSvcClient) Subscribe(observer meta.Observer) {
	sc.BaseNotifier.Subscribe(observer)

	close(sc.waitForSubscription)

	// after the subscription is done, we temporarily pause the execution until the
	// cache is fully loaded
	sc.log.Info("waiting for K8s metadata synchronization", "timeout", sc.syncTimeout)
	select {
	case <-sc.waitForSynchronization:
		sc.log.Debug("K8s metadata cache service synchronized")
	case <-sc.ctx.Done():
		sc.log.Debug("context done. Nothing to do")
	case <-time.After(sc.syncTimeout):
		sc.log.Warn("timed out while waiting for K8s metadata synchronization. Some metadata might be temporarily missing." +
			" If this is expected due to the size of your cluster, you might want to increase the timeout via" +
			" the BEYLA_KUBE_INFORMERS_SYNC_TIMEOUT configuration option")
	}
}
