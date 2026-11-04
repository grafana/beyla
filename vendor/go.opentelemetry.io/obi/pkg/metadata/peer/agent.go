// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/selection"
)

type Agent struct {
	cfg      MetadataConfig
	network  network
	store    *localStore
	exchange exchange
}

func New(ctx context.Context, cfg MetadataConfig, hostname string, serviceGraphEnabled bool,
	metricsPIDs selection.PIDSelector, metricProtocols *instrumentations.InstrumentationSelection,
) (*Agent, error) {
	cfg = cfg.WithDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if !validName(hostname) {
		return nil, errors.New("peer metadata requires a valid hostname")
	}

	network, err := localNetwork(cfg.PeerCIDRs)
	if err != nil {
		return nil, err
	}

	store := newStore(hostname, cfg)
	store.graphEnabled = serviceGraphEnabled
	store.metricsPIDs = metricsPIDs
	if metricProtocols != nil {
		store.metricProtocols = *metricProtocols
	}

	exchange, err := newExchange(ctx, cfg, store, network)
	if err != nil {
		return nil, err
	}

	agent := &Agent{
		cfg:      cfg,
		network:  network,
		store:    store,
		exchange: exchange,
	}

	context.AfterFunc(ctx, agent.Close)
	return agent, nil
}

func (a *Agent) Close() {
	a.exchange.close()
}

// Run tracks process inventory, expires caller observations, and runs the metadata exchange until cancellation.
func (a *Agent) Run(ctx context.Context, events <-chan exec.ProcessEvent) {
	defer a.Close()

	// We need another afterfunc here, since the context is a child of
	// the context we see in New().
	stopClose := context.AfterFunc(ctx, a.Close)
	defer stopClose()

	var workers sync.WaitGroup

	workers.Go(func() {
		runInventory(ctx, events, a.store, a.cfg.RefreshInterval)
	})

	workers.Go(func() {
		a.expireCallers(ctx)
	})

	a.exchange.run(ctx)
	workers.Wait()
}

// expireCallers periodically drops expired caller observations from the local store.
func (a *Agent) expireCallers(ctx context.Context) {
	ticker := time.NewTicker(pollInterval(&a.cfg))
	defer ticker.Stop()

	for {
		a.store.expire(time.Now())

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// pollInterval keeps background housekeeping responsive relative to the refresh interval.
func pollInterval(cfg *MetadataConfig) time.Duration {
	return max(time.Millisecond, min(time.Second, cfg.RefreshInterval/4))
}

// Decorate records outgoing callers and enriches spans from available peer metadata.
func (a *Agent) Decorate(span *request.Span, now time.Time) {
	if span.Service.ProcPID == app.PID(os.Getpid()) {
		return
	}

	endpoint := Endpoint{Port: span.HostPort}

	// Read the Host IP address, if we fail and it's a client span
	// there's nothing we can do.
	destination, err := netip.ParseAddr(span.Host)
	if err == nil {
		destination = destination.Unmap()
		endpoint.IP = destination.String()
	} else if span.IsClientSpan() {
		return
	}

	if span.IsClientSpan() {
		if !a.network.isLocal(destination) && !a.network.permits(destination) {
			return
		}

		a.decorateClient(span, endpoint, now)
		return
	}

	service := a.resolveCaller(span.Peer, endpoint, now)
	if service.Name == "" {
		return
	}

	span.PeerName = service.Name
	span.OtherNamespace = service.Namespace
}

// decorateClient records outgoing callers and enriches the destination.
func (a *Agent) decorateClient(span *request.Span, destination Endpoint, now time.Time) {
	caller := a.store.serviceFor(span.Service)
	a.store.observe(destination, caller, now)
	service, ignoreClientCount := a.resolveDestination(destination, caller, span.Type, now)
	if service.Name == "" {
		return
	}

	span.HostName = service.Name
	span.OtherNamespace = service.Namespace
	if ignoreClientCount && span.Type != request.EventTypeFailedConnect {
		request.SetIgnoreServiceGraphClientCount(span)
	}
}

// resolveDestination identifies the service and whether to suppress the client graph count.
func (a *Agent) resolveDestination(destination Endpoint, caller Service, event request.EventType, now time.Time) (Service, bool) {
	address, err := netip.ParseAddr(destination.IP)
	if err != nil {
		return Service{}, false
	}

	address = address.Unmap()
	if a.network.isLocal(address) {
		service, match := a.store.destinationService(destination)
		return service, protocolMetricsEnabled(&a.store.metricProtocols, event) &&
			(match == listenerAmbiguous || (match == listenerUnique && service.ServiceGraph))
	}

	if !a.network.permits(address) {
		return Service{}, false
	}

	snapshot, fetchedAt := a.exchange.lookup(address, now)
	if snapshot == nil {
		return Service{}, false
	}

	service, match := snapshot.destinationService(destination)
	ignoreClientCount := protocolMetricsEnabled(snapshot.metricProtocols, event) &&
		(match == listenerAmbiguous || (match == listenerUnique && service.ServiceGraph && snapshot.knowsCaller(destination, caller, now.Sub(fetchedAt))))
	return service, ignoreClientCount
}

// resolveCaller identifies a caller from recent observations, using its hostname as a fallback.
func (a *Agent) resolveCaller(remoteIP string, destination Endpoint, now time.Time) Service {
	address, err := netip.ParseAddr(remoteIP)
	if err != nil {
		return Service{}
	}

	address = address.Unmap()
	if a.network.isLocal(address) {
		return a.store.callerService(destination, now)
	}

	if !a.network.permits(address) {
		return Service{}
	}

	snapshot, fetchedAt := a.exchange.lookup(address, now)
	if snapshot == nil {
		return Service{}
	}

	return snapshot.callerService(destination, now.Sub(fetchedAt))
}
