// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"
)

func tlsConfigs(cfg MetadataTLSConfig) (*tls.Config, *tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil, nil
	}

	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("loading peer metadata certificate: %w", err)
	}

	server := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	client := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName}
	if cfg.CAFile == "" {
		return server, client, nil
	}

	data, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, nil, fmt.Errorf("loading peer metadata CA: %w", err)
	}

	client.RootCAs = x509.NewCertPool()
	if !client.RootCAs.AppendCertsFromPEM(data) {
		return nil, nil, errors.New("peer metadata ca_file contains no certificates")
	}

	return server, client, nil
}

func newHTTPClient(cfg MetadataConfig, clientTLS *tls.Config) *http.Client {
	return &http.Client{
		Timeout: cfg.RequestTimeout,
		Transport: &http.Transport{
			DialContext:         (&net.Dialer{Timeout: cfg.RequestTimeout}).DialContext,
			TLSClientConfig:     clientTLS,
			TLSHandshakeTimeout: cfg.RequestTimeout,
			MaxIdleConns:        cfg.MaxPeers,
			MaxIdleConnsPerHost: 1,
			MaxConnsPerHost:     1,
			IdleConnTimeout:     3 * cfg.RefreshInterval,
			DisableCompression:  true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func metadataHandler(store *localStore, cfg MetadataConfig, peers network, cache *peerCache) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(MetadataPath, func(w http.ResponseWriter, r *http.Request) {
		requester, err := netip.ParseAddrPort(r.RemoteAddr)
		if err != nil || !peers.permits(requester.Addr().Unmap()) {
			http.Error(w, "peer address is not permitted", http.StatusForbidden)
			return
		}

		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if cfg.Token != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+cfg.Token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		targets, err := queryTargets(r, requester.Addr().Unmap())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		now := time.Now()
		snapshot := store.snapshot(targets, now)
		if cache != nil {
			snapshot.KnownCallers = cache.knownCallers(requester.Addr().Unmap(), now)
		}
		if err := filterListeners(&snapshot, r.URL.Query()); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		writeSnapshot(w, snapshot, cfg.MaxResponseBytes)
	})

	return mux
}

func queryTargets(r *http.Request, requester netip.Addr) (map[string]struct{}, error) {
	for _, value := range r.URL.Query()["target"] {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return nil, errors.New("target must be an IP address")
		}
		if addr.Unmap() != requester {
			return nil, errors.New("target must match requester address")
		}
	}

	return map[string]struct{}{requester.String(): {}}, nil
}

func filterListeners(snapshot *Snapshot, query url.Values) error {
	if query.Get("port") == "" && query.Get("ip") == "" {
		return nil
	}

	port, err := queryPort(query.Get("port"))
	if err != nil {
		return err
	}

	var ip netip.Addr
	if value := query.Get("ip"); value != "" {
		ip, err = netip.ParseAddr(value)
		if err != nil {
			return errors.New("ip must be an IP address")
		}
		ip = ip.Unmap()
	}

	listeners := make([]Listener, 0)
	services := map[Service]struct{}{}
	for _, listener := range snapshot.Listeners {
		addr, _ := netip.ParseAddr(listener.Endpoint.IP)
		if port != 0 && listener.Endpoint.Port != port {
			continue
		}

		if ip.IsValid() && ip != addr && !addr.IsUnspecified() {
			continue
		}

		if ip.Is6() && addr.Is4() {
			continue
		}

		listeners = append(listeners, listener)
		services[listener.Service] = struct{}{}
	}

	snapshot.Listeners = listeners
	snapshot.Services = slices.AppendSeq(make([]Service, 0, len(services)), maps.Keys(services))
	return nil
}

func queryPort(value string) (int, error) {
	if value == "" {
		return 0, nil
	}

	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}

	return port, nil
}

func writeSnapshot(w http.ResponseWriter, snapshot Snapshot, limit int) {
	data, err := json.Marshal(snapshot)
	if err != nil || len(data) > limit {
		http.Error(w, "metadata response exceeds size limit", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	_, _ = w.Write(data)
}

func fetchSnapshot(ctx context.Context, client *http.Client, cfg MetadataConfig, address netip.Addr) (*Snapshot, int, error) {
	scheme := "http"
	if cfg.TLS.Enabled {
		scheme = "https"
	}

	u := url.URL{
		Scheme: scheme,
		Host:   net.JoinHostPort(address.String(), strconv.Itoa(cfg.Port)),
		Path:   MetadataPath,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}

	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}

	response, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("peer metadata returned HTTP %d", response.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, int64(cfg.MaxResponseBytes)+1))
	if err != nil {
		return nil, 0, err
	}

	if len(data) > cfg.MaxResponseBytes {
		return nil, 0, errors.New("peer metadata response exceeds size limit")
	}

	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return nil, 0, err
	}

	if err := validateSnapshot(&snapshot, cfg.CallerTTL); err != nil {
		return nil, 0, err
	}

	return &snapshot, len(data), nil
}

func validateSnapshot(snapshot *Snapshot, callerTTL time.Duration) error {
	if snapshot.Version != ProtocolVersion || !validName(snapshot.Hostname) {
		return errors.New("invalid peer metadata version or hostname")
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
