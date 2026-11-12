// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"
	"unicode/utf8"

	"google.golang.org/grpc"
	grpcbackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/obi/pkg/metadata/peer/metadatapb"
)

// serverTLSConfig serves the configured certificate. It returns nil when TLS is disabled.
func serverTLSConfig(cfg MetadataTLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading peer metadata certificate: %w", err)
	}

	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, nil
}

// clientTLSConfig verifies servers against the configured CA, or the system roots when there is none.
// It returns nil when TLS is disabled.
func clientTLSConfig(cfg MetadataTLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	client := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName}
	if cfg.CAFile == "" {
		return client, nil
	}

	data, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("loading peer metadata CA: %w", err)
	}

	client.RootCAs = x509.NewCertPool()
	if !client.RootCAs.AppendCertsFromPEM(data) {
		return nil, errors.New("peer metadata ca_file contains no certificates")
	}

	return client, nil
}

// maxPeerRequestBytes bounds the headers and body of an incoming snapshot request, which carries no data.
const maxPeerRequestBytes = 16 << 10

func peerServerOptions(cfg *MetadataConfig, serverTLS *tls.Config) []grpc.ServerOption {
	options := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(maxPeerRequestBytes),
		grpc.MaxHeaderListSize(maxPeerRequestBytes),
		grpc.MaxSendMsgSize(cfg.MaxResponseBytes),
		grpc.ConnectionTimeout(cfg.RequestTimeout),
		grpc.KeepaliveParams(keepalive.ServerParameters{MaxConnectionIdle: 3 * cfg.RefreshInterval}),
		grpc.InTapHandle(requestTimeoutTap(cfg.RequestTimeout)),
		grpc.UnaryInterceptor(bearerTokenInterceptor(cfg.Token)),
	}
	if serverTLS != nil {
		options = append(options, grpc.Creds(credentials.NewTLS(serverTLS)))
	}

	return options
}

// requestTimeoutTap bounds each request with a server-owned deadline, covering request decoding, which runs
// before any interceptor. Otherwise, a client without a deadline could withhold the request message indefinitely.
func requestTimeoutTap(timeout time.Duration) tap.ServerInHandle {
	return func(ctx context.Context, _ *tap.Info) (context.Context, error) {
		// gRPC cancels the parent stream context when the stream ends, which also releases this timeout.
		ctx, _ = context.WithTimeout(ctx, timeout) //nolint:govet // the returned context replaces the stream context
		return ctx, nil
	}
}

// bearerTokenInterceptor rejects requests without the configured bearer token. An empty token disables the check.
func bearerTokenInterceptor(token string) grpc.UnaryServerInterceptor {
	expected := []byte("Bearer " + token)
	return func(ctx context.Context, request any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if token == "" {
			return handler(ctx, request)
		}

		values := metadata.ValueFromIncomingContext(ctx, "authorization")
		if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), expected) != 1 {
			return nil, status.Error(codes.Unauthenticated, "unauthorized")
		}

		return handler(ctx, request)
	}
}

// requesterAddress returns the source address of the connection that sent the request.
func requesterAddress(ctx context.Context) (netip.Addr, bool) {
	requester, ok := grpcpeer.FromContext(ctx)
	if !ok || requester.Addr == nil {
		return netip.Addr{}, false
	}

	address, err := netip.ParseAddrPort(requester.Addr.String())
	if err != nil {
		return netip.Addr{}, false
	}

	return address.Addr().Unmap(), true
}

var errPeerClientsClosed = errors.New("peer metadata clients closed")

// peerClients keeps one connection per remote agent, so refreshes reuse it.
type peerClients struct {
	mu      sync.Mutex
	port    string
	options []grpc.DialOption
	conns   map[netip.Addr]*grpc.ClientConn
	closed  bool
}

func newPeerClients(cfg *MetadataConfig, clientTLS *tls.Config, options ...grpc.DialOption) *peerClients {
	dialOptions := clientDialOptions(cfg, clientTLS)
	// Callers are scoped to the TCP source address, so peers must be dialed directly, never through a proxy.
	dialOptions = append(dialOptions, grpc.WithNoProxy())
	dialOptions = append(dialOptions, options...)

	return &peerClients{
		port:    strconv.Itoa(cfg.Port),
		options: dialOptions,
		conns:   map[netip.Addr]*grpc.ClientConn{},
	}
}

// clientDialOptions configures the connections to other agents or to the central metadata service.
func clientDialOptions(cfg *MetadataConfig, clientTLS *tls.Config) []grpc.DialOption {
	transport := insecure.NewCredentials()
	if clientTLS != nil {
		transport = credentials.NewTLS(clientTLS)
	}

	// Cap reconnection backoff like peer refreshes, so a recovered server is not probed later than its retry.
	reconnect := grpcbackoff.DefaultConfig
	reconnect.MaxDelay = backoff(cfg.RefreshInterval, maxFailures)

	return []grpc.DialOption{
		grpc.WithTransportCredentials(transport),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(cfg.MaxResponseBytes)),
		grpc.WithConnectParams(grpc.ConnectParams{Backoff: reconnect, MinConnectTimeout: cfg.RequestTimeout}),
		grpc.WithIdleTimeout(3 * cfg.RefreshInterval),
	}
}

func (c *peerClients) get(address netip.Addr) (metadatapb.PeerMetadataServiceClient, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, errPeerClientsClosed
	}

	conn, exists := c.conns[address]
	if !exists {
		var err error
		conn, err = grpc.NewClient(net.JoinHostPort(address.String(), c.port), c.options...)
		if err != nil {
			return nil, err
		}
		c.conns[address] = conn
	}

	return metadatapb.NewPeerMetadataServiceClient(conn), nil
}

// retain closes the connections to the addresses that keep rejects.
func (c *peerClients) retain(keep func(netip.Addr) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for address, conn := range c.conns {
		if !keep(address) {
			_ = conn.Close()
			delete(c.conns, address)
		}
	}
}

// close closes all connections and rejects later requests, so workers still running cannot open new ones.
func (c *peerClients) close() {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()

	c.retain(func(netip.Addr) bool { return false })
}

func fetchSnapshot(ctx context.Context, client metadatapb.PeerMetadataServiceClient, cfg *MetadataConfig) (*Snapshot, int, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.RequestTimeout)
	defer cancel()

	message, err := client.GetSnapshot(withBearerToken(ctx, cfg.Token), &metadatapb.GetSnapshotRequest{})
	if err != nil {
		return nil, 0, err
	}

	return decodeSnapshot(message, cfg.CallerTTL)
}

// withBearerToken authenticates outgoing requests with the token, unless it is empty.
func withBearerToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}

	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

// decodeSnapshot validates a received snapshot and returns it with its encoded size.
func decodeSnapshot(message *metadatapb.Snapshot, callerTTL time.Duration) (*Snapshot, int, error) {
	snapshot := snapshotFromProto(message)
	if err := validateSnapshot(&snapshot, callerTTL); err != nil {
		return nil, 0, err
	}

	return &snapshot, proto.Size(message), nil
}

func validateSnapshot(snapshot *Snapshot, callerTTL time.Duration) error {
	if !validName(snapshot.Hostname) {
		return errors.New("invalid peer metadata hostname")
	}

	for _, service := range snapshot.Services {
		if !validService(service) {
			return errors.New("invalid peer service")
		}
	}

	for i := range snapshot.Listeners {
		listener := &snapshot.Listeners[i]
		if !validService(listener.Service) || !normalizeEndpoint(&listener.Endpoint) {
			return errors.New("invalid peer listener")
		}
	}

	if snapshot.CallerAmbiguityMillis < 0 {
		return errors.New("invalid caller ambiguity lifetime")
	}

	snapshot.CallerAmbiguityMillis = min(snapshot.CallerAmbiguityMillis, callerTTL.Milliseconds())
	if err := validateCallers(snapshot.Callers, callerTTL); err != nil {
		return err
	}
	return validateCallers(snapshot.KnownCallers, callerTTL)
}

func validateCallers(callers []Caller, ttl time.Duration) error {
	for i := range callers {
		caller := &callers[i]
		if !normalizeEndpoint(&caller.Destination) {
			return errors.New("invalid caller destination")
		}

		for j := range caller.Services {
			service := &caller.Services[j]
			if !validService(service.Service) || service.RemainingMillis < 0 {
				return errors.New("invalid caller service")
			}
			service.RemainingMillis = min(service.RemainingMillis, ttl.Milliseconds())
		}
	}

	return nil
}

func validName(name string) bool {
	return name != "" && len(name) <= 1024 && utf8.ValidString(name)
}

func validService(service Service) bool {
	return validName(service.Name) && len(service.Namespace) <= 1024 && utf8.ValidString(service.Namespace)
}

func normalizeEndpoint(endpoint *Endpoint) bool {
	addr, err := netip.ParseAddr(endpoint.IP)
	if err != nil || endpoint.Port < 1 || endpoint.Port > 65535 {
		return false
	}

	endpoint.IP = addr.Unmap().String()
	return true
}
