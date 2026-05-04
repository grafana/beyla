// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package service // import "go.opentelemetry.io/obi/pkg/kube/kubecache/service"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"go.opentelemetry.io/obi/pkg/internal/helpers/sync"
	"go.opentelemetry.io/obi/pkg/kube/kubecache"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/instrument"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/meta"
)

// InformersCache configures and starts the gRPC service
type InformersCache struct {
	informer.UnimplementedEventStreamServiceServer

	Config *kubecache.Config

	started   atomic.Bool
	informers *meta.Informers
	log       *slog.Logger

	metrics instrument.InternalMetrics
}

func (ic *InformersCache) Run(ctx context.Context, opts ...meta.InformerOption) error {
	if ic.started.Swap(true) {
		return errors.New("server already started")
	}
	ic.metrics = instrument.FromContext(ctx)
	ic.log = slog.With("component", "server.InformersCache")

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", ic.Config.Port))
	if err != nil {
		return fmt.Errorf("starting TCP connection: %w", err)
	}

	ic.informers, err = meta.InitInformers(ctx, opts...)
	if err != nil {
		return fmt.Errorf("initializing informers: %w", err)
	}

	s := grpc.NewServer(
		// TODO: configure other aspects (e.g. secure connections)
		grpc.MaxConcurrentStreams(uint32(ic.Config.MaxConnections)),
	)
	informer.RegisterEventStreamServiceServer(s, ic)

	ic.log.Info("server listening", "port", ic.Config.Port)

	errs := make(chan error, 1)
	go func() {
		if err := s.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errs <- fmt.Errorf("failed to serve: %w", err)
		}
		close(errs)
	}()
	select {
	case <-ctx.Done():
		s.Stop()
		return <-errs
	case err := <-errs:
		return err
	}
}

func effectiveSendTimeout(configured time.Duration) time.Duration {
	if configured == 0 {
		return kubecache.DefaultConfig.SendTimeout
	}
	return configured
}

// Subscribe method of the generated protobuf definition
func (ic *InformersCache) Subscribe(msg *informer.SubscribeMessage, server informer.EventStreamService_SubscribeServer) error {
	// extract peer information to identify it
	p, ok := peer.FromContext(server.Context())
	if !ok {
		return errors.New("failed to extract peer information")
	}
	ic.metrics.ClientConnect()
	o := &connection{
		log:         ic.log.With("clientID", p.Addr.String()),
		id:          p.Addr.String(),
		server:      server,
		sendTimeout: effectiveSendTimeout(ic.Config.SendTimeout),
		metrics:     ic.metrics,
		fromEpoch:   msg.GetFromTimestampEpoch(),
		messages:    sync.NewQueue[*informer.Event](),
	}
	ic.log.Info("client subscribed", "id", o.ID(),
		"fromEpoch", o.fromEpoch,
		"fromLast", time.Since(time.Unix(o.fromEpoch, 0)))
	ic.informers.Subscribe(o)
	go func() {
		<-server.Context().Done()
		o.messages.Enqueue(nil)
	}()
	// Keep the connection open
	o.handleMessagesQueue(server.Context())
	ic.informers.Unsubscribe(o)
	ic.metrics.ClientDisconnect()
	ic.log.Info("client disconnected", "id", o.ID())
	return nil
}

// connection implements the meta.Observer pattern to store the handle to
// each client connection subscription
type connection struct {
	log *slog.Logger

	id     string
	server grpc.ServerStreamingServer[informer.Event]

	sendTimeout time.Duration

	metrics instrument.InternalMetrics
	// fromEpoch filters events whose timestamp is lower than its value
	fromEpoch int64
	messages  *sync.Queue[*informer.Event]
}

func (o *connection) ID() string {
	return o.id
}

// FromEpoch implements the Timestamped interface to allow filtering the returned list by
// a given timestamp in unix seconds (epoch)
func (o *connection) FromEpoch() int64 {
	return o.fromEpoch
}

func (o *connection) On(event *informer.Event) error {
	// the client asked for events happening after their last successfully received event
	// so ignore older events to save memory and network
	if event.Type != informer.EventType_SYNC_FINISHED && event.Resource != nil && event.Resource.StatusTimeEpoch < o.fromEpoch {
		return nil
	}
	o.metrics.MessageSubmit()
	o.messages.Enqueue(event)
	return nil
}

func (o *connection) handleMessagesQueue(ctx context.Context) {
	timer := time.NewTimer(o.sendTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			o.log.Debug("context done. Closing client connection")
			return
		default:
			event := o.messages.Dequeue()
			if event == nil {
				return
			}
			if err := o.sendWithTimeout(ctx, timer, event); err != nil {
				return
			}
		}
	}
}

// sendWithTimeout sends event and drops the connection if Send blocks longer
// than o.sendTimeout (enforced per-Send). Returns a non-nil error whenever the
// caller should stop processing the queue.
func (o *connection) sendWithTimeout(ctx context.Context, timer *time.Timer, event *informer.Event) error {
	sendErr := make(chan error, 1)
	go func() { sendErr <- o.server.Send(event) }()

	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(o.sendTimeout)

	select {
	case err := <-sendErr:
		if err != nil {
			o.log.Warn("Error sending message. Closing client connection", "clientID", o.ID(), "error", err)
			o.metrics.MessageError()
			return err
		}
		o.metrics.MessageSucceed()
		return nil
	case <-timer.C:
		o.log.Warn("Send timed out. Closing client connection", "clientID", o.ID(), "timeout", o.sendTimeout)
		o.metrics.MessageTimeout()
		// sendErr is buffered; the goroutine exits when gRPC closes the stream on Subscribe's return.
		return context.DeadlineExceeded
	case <-ctx.Done():
		o.log.Debug("context done. Closing client connection")
		return ctx.Err()
	}
}
