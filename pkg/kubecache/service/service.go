package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"

	"github.com/grafana/beyla/pkg/kubecache/informer"
	"github.com/grafana/beyla/pkg/kubecache/meta"
)

// InformersCache configures and starts the gRPC service
type InformersCache struct {
	informer.UnimplementedEventStreamServiceServer

	Port int

	started   atomic.Bool
	informers *meta.Informers
	log       *slog.Logger
}

func (ic *InformersCache) Run(ctx context.Context, opts ...meta.InformerOption) error {
	if ic.started.Swap(true) {
		return errors.New("server already started")
	}
	ic.log = slog.With("component", "server.InformersCache")

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", ic.Port))
	if err != nil {
		return fmt.Errorf("starting TCP connection: %w", err)
	}

	ic.informers, err = meta.InitInformers(ctx, opts...)
	if err != nil {
		return fmt.Errorf("initializing informers: %w", err)
	}

	s := grpc.NewServer()
	informer.RegisterEventStreamServiceServer(s, ic)

	ic.log.Info("server listening", "port", ic.Port)
	if err := s.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %w", err)
	}
	return nil
}

// Subscribe method of the generated protobuf definition
func (ic *InformersCache) Subscribe(_ *informer.SubscribeMessage, server informer.EventStreamService_SubscribeServer) error {
	// extract peer information to identify it
	p, ok := peer.FromContext(server.Context())
	if !ok {
		return fmt.Errorf("failed to extract peer information")
	}
	o := &connection{id: p.Addr.String(), server: server}
	ic.log.Debug("subscribed component", "id", o.ID())
	ic.informers.Subscribe(o)
	// Keep the connection open
	<-server.Context().Done()
	ic.log.Debug("client disconnected", "id", o.ID())
	ic.informers.Unsubscribe(o)
	return nil
}

// connection implements the meta.Observer pattern to store the handle to
// each client connection subscription
type connection struct {
	id     string
	server grpc.ServerStreamingServer[informer.Event]
}

func (o *connection) ID() string {
	return o.id
}

func (o *connection) On(event *informer.Event) {
	if err := o.server.Send(event); err != nil {
		slog.Error("sending message", "clientID", o.ID(), "error", err)
	}
}
