package service

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

	"github.com/grafana/beyla/pkg/kubecache"
	"github.com/grafana/beyla/pkg/kubecache/informer"
	"github.com/grafana/beyla/pkg/kubecache/meta"
)

const defaultSendTimeout = 10 * time.Second

// InformersCache configures and starts the gRPC service
type InformersCache struct {
	informer.UnimplementedEventStreamServiceServer

	Config *kubecache.Config

	started   atomic.Bool
	informers *meta.Informers
	log       *slog.Logger

	// TODO: allow configuring by user
	SendTimeout time.Duration
}

func (ic *InformersCache) Run(ctx context.Context, opts ...meta.InformerOption) error {
	if ic.SendTimeout == 0 {
		ic.SendTimeout = defaultSendTimeout
	}
	if ic.started.Swap(true) {
		return errors.New("server already started")
	}
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
		if err := s.Serve(lis); err != nil {
			errs <- fmt.Errorf("failed to serve: %w", err)
		}
		close(errs)
	}()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errs:
		return err
	}
}

// Subscribe method of the generated protobuf definition
func (ic *InformersCache) Subscribe(_ *informer.SubscribeMessage, server informer.EventStreamService_SubscribeServer) error {
	// extract peer information to identify it
	p, ok := peer.FromContext(server.Context())
	if !ok {
		return fmt.Errorf("failed to extract peer information")
	}
	connCtx, cancel := context.WithCancel(server.Context())
	o := &connection{
		cancel:      cancel,
		id:          p.Addr.String(),
		server:      server,
		sendTimeout: ic.SendTimeout,
	}
	ic.log.Info("client subscribed", "id", o.ID())
	ic.informers.Subscribe(o)
	// Keep the connection open
	<-connCtx.Done()
	ic.log.Info("client disconnected", "id", o.ID())
	ic.informers.Unsubscribe(o)
	return nil
}

// connection implements the meta.Observer pattern to store the handle to
// each client connection subscription
type connection struct {
	cancel func()

	id     string
	server grpc.ServerStreamingServer[informer.Event]

	sendTimeout time.Duration
}

func (o *connection) ID() string {
	return o.id
}

func (o *connection) On(event *informer.Event) error {
	// Theoretically Go is ready to run hundreds of thousands of parallel goroutines
	done := make(chan error, 1)
	go func() {
		if err := o.server.Send(event); err != nil {
			slog.Debug("sending message. Closing client connection", "clientID", o.ID(), "error", err)
			o.cancel()
			done <- err
		}
		close(done)
	}()
	timeout := time.After(o.sendTimeout)
	select {
	case err := <-done:
		// might be just nil if the connection succeeded
		return err
	case <-timeout:
		o.cancel()
		return errors.New("timeout sending message to client. Closing connection " + o.ID())
	}
}
