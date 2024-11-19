package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"

	"github.com/grafana/beyla/pkg/kubecache"
	"github.com/grafana/beyla/pkg/kubecache/informer"
	"github.com/grafana/beyla/pkg/kubecache/instrument"
	"github.com/grafana/beyla/pkg/kubecache/meta"
)

const defaultSendTimeout = 10 * time.Second
const barrierBufferLen = 10

// InformersCache configures and starts the gRPC service
type InformersCache struct {
	informer.UnimplementedEventStreamServiceServer

	Config *kubecache.Config

	started   atomic.Bool
	informers *meta.Informers
	log       *slog.Logger

	// TODO: allow configuring by user
	SendTimeout time.Duration

	metrics instrument.InternalMetrics

	connections *connectionInterceptor
}

// connection interceptor hooks into the credentials negotiation
// to store each client connection, which can be prematurely closed
// if we detect that the client connection is blocked
type connectionInterceptor struct {
	credentials.TransportCredentials
	log   *slog.Logger
	conns sync.Map
}

func (ci *connectionInterceptor) ServerHandshake(conn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, authInfo, err := ci.TransportCredentials.ServerHandshake(conn)
	if err == nil {
		id := conn.RemoteAddr().String()
		ci.conns.Store(id, conn)
	}
	return conn, authInfo, err
}

func (ci *connectionInterceptor) closeConnection(id string) {
	ci.log.Debug("closing connection", "id", id)
	if conn, ok := ci.conns.LoadAndDelete(id); ok {
		if err := conn.(net.Conn).Close(); err != nil {
			ci.log.Debug("error closing connection", "id", id, "error", err)
		}
	}
}

func (ic *InformersCache) Run(ctx context.Context, opts ...meta.InformerOption) error {
	if ic.SendTimeout == 0 {
		ic.SendTimeout = defaultSendTimeout
	}
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

	// TODO: allow configuring credentials
	ic.connections = &connectionInterceptor{TransportCredentials: insecure.NewCredentials(), log: ic.log}
	s := grpc.NewServer(
		// TODO: configure other aspects (e.g. secure connections)
		grpc.MaxConcurrentStreams(uint32(ic.Config.MaxConnections)),
		grpc.Creds(ic.connections),
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
	ic.metrics.ClientConnect()
	connectionID := p.Addr.String()
	connCtx, cancel := context.WithCancel(server.Context())
	o := &connection{
		log:         ic.log.With("connectionID", connectionID),
		ctx:         connCtx,
		cancel:      cancel,
		id:          connectionID,
		server:      server,
		sendTimeout: ic.SendTimeout,
		metrics:     ic.metrics,
		barrier:     make(chan struct{}, barrierBufferLen),
	}
	o.log.Info("client subscribed")

	go ic.informers.Subscribe(o)

	o.watchForActiveConnection()

	// canceling the context in case the client disconnected due to timeout
	ic.connections.closeConnection(o.ID())
	ic.metrics.ClientDisconnect()
	o.log.Info("client disconnected")
	ic.informers.Unsubscribe(o)
	return nil
}

// connection implements the meta.Observer pattern to store the handle to
// each client connection subscription
type connection struct {
	log    *slog.Logger
	ctx    context.Context
	cancel context.CancelFunc

	id     string
	server grpc.ServerStreamingServer[informer.Event]

	sendTimeout time.Duration

	metrics instrument.InternalMetrics
	barrier chan struct{}
}

func (o *connection) ID() string {
	return o.id
}

// watchForActiveConnection is a blocking function that waits for the client to
// finish its connection. It also unblocks the connection if a timeout
// is detected for the gRPC Send method (this method uses barriers to coordinate the
// submission of messages with the On(...) method).
func (o *connection) watchForActiveConnection() {
	for {
		// wait for On(...) to be called
		select {
		case <-o.ctx.Done():
			// client disconnected. Exiting
			return
		case <-o.barrier:
			// On(...) started. Continue
		}

		// wait for On(...) to finish, or a timeout
		select {
		case <-o.ctx.Done():
			// client disconnected. Exiting
			return
		case <-time.After(o.sendTimeout):
			// timeout! exit to cancel the connection
			o.log.Debug("detected timeout. Forcing connection close")
			return
		case <-o.barrier:
			// On(...) finished. Continue
		}
	}
}

func (o *connection) On(event *informer.Event) error {
	o.metrics.MessageSubmit()
	if err := o.unlockBarrier("BEFORE"); err != nil {
		return err
	}
	err := o.server.Send(event)
	if err != nil {
		o.log.Debug("sending message. Closing client context", "error", err)
		o.cancel()
		o.metrics.MessageError()
		return err
	}
	o.metrics.MessageSucceed()
	return o.unlockBarrier("AFTER")
}

// TODO: remove this method and use directly o.barrier <- struct{}{}
// after we verify the execution is not blocked here
func (o *connection) unlockBarrier(position string) error {
	select {
	case o.barrier <- struct{}{}:
		return nil
	case <-time.After(o.sendTimeout):
		return fmt.Errorf("barrier blocked %s server.Send. This mostly looks as a bug", position)
	}
}
