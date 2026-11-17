// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"go.opentelemetry.io/obi/pkg/metadata/peer/metadatapb"
)

// CentralServer receives the metadata each agent publishes and serves it to the agents that look it up.
type CentralServer struct {
	metadatapb.UnimplementedMetadataServiceServer

	cfg     CentralServerConfig
	network network
	store   *centralStore
	server  *grpc.Server
}

func NewCentralServer(cfg *CentralServerConfig) (*CentralServer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	network, err := cfg.publishedNetwork()
	if err != nil {
		return nil, err
	}

	serverTLS, err := serverTLSConfig(cfg.TLS)
	if err != nil {
		return nil, err
	}

	s := &CentralServer{
		cfg:     *cfg,
		network: network,
		store:   newCentralStore(cfg.HostTTL, cfg.MaxHosts),
	}

	options := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(cfg.MaxMessageBytes),
		grpc.MaxSendMsgSize(cfg.MaxMessageBytes),
		grpc.UnaryInterceptor(bearerTokenInterceptor(cfg.Token)),
	}
	if serverTLS != nil {
		options = append(options, grpc.Creds(credentials.NewTLS(serverTLS)))
	}

	s.server = grpc.NewServer(options...)
	metadatapb.RegisterMetadataServiceServer(s.server, s)
	return s, nil
}

// Run listens on the configured address and serves until cancellation.
func (s *CentralServer) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(s.cfg.ListenAddress, strconv.Itoa(s.cfg.Port)))
	if err != nil {
		return fmt.Errorf("listening for metadata service: %w", err)
	}

	return s.Serve(ctx, listener)
}

// Serve serves on the listener and expires silent hosts until cancellation.
func (s *CentralServer) Serve(ctx context.Context, listener net.Listener) error {
	stopExpiry := s.runExpiry(ctx)
	defer stopExpiry()

	stopServer := context.AfterFunc(ctx, s.server.Stop)
	defer stopServer()

	slog.Info("metadata service listening", "address", listener.Addr())
	if err := s.server.Serve(listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("serving metadata service: %w", err)
	}

	return nil
}

func (s *CentralServer) runExpiry(ctx context.Context) func() {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(max(time.Millisecond, min(time.Second, s.cfg.HostTTL/4)))
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				s.store.expire(now)
			}
		}
	}()

	return func() { cancel(); <-done }
}

func (s *CentralServer) Publish(_ context.Context, request *metadatapb.PublishRequest) (*metadatapb.PublishResponse, error) {
	hostID := request.GetHostId()
	if !validName(hostID) {
		return nil, status.Error(codes.InvalidArgument, "a valid host ID is required")
	}

	addresses, err := s.parseAddresses(request.GetAddresses())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	if len(addresses) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one host address is required")
	}

	snapshot := snapshotFromProto(request.GetSnapshot())
	if err := validateSnapshot(&snapshot, s.cfg.CallerTTL); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	// Acknowledgements describe what a host learned from its peers, which the service derives itself.
	snapshot.KnownCallers = nil

	if err := s.store.publish(hostID, addresses, snapshot, time.Now()); err != nil {
		return nil, status.Error(codes.ResourceExhausted, err.Error())
	}

	return &metadatapb.PublishResponse{}, nil
}

func (s *CentralServer) Lookup(_ context.Context, request *metadatapb.LookupRequest) (*metadatapb.LookupResponse, error) {
	address, err := netip.ParseAddr(request.GetAddress())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "address must be an IP address")
	}

	requester, err := s.parseAddresses(request.GetRequesterAddresses())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	snapshot, found := s.store.lookup(address.Unmap(), requester, time.Now())
	if !found {
		return &metadatapb.LookupResponse{}, nil
	}

	return &metadatapb.LookupResponse{Snapshot: snapshotToProto(snapshot)}, nil
}

// parseAddresses accepts unique host addresses within the permitted networks.
func (s *CentralServer) parseAddresses(values []string) ([]netip.Addr, error) {
	addresses := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, errors.New("host addresses must be IP addresses")
		}

		address = address.Unmap()
		if !s.network.permits(address) {
			return nil, fmt.Errorf("host address %s is not permitted", address)
		}

		addresses = append(addresses, address)
	}

	slices.SortFunc(addresses, netip.Addr.Compare)
	return slices.Compact(addresses), nil
}
