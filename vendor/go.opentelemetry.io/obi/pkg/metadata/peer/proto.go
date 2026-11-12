// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package peer // import "go.opentelemetry.io/obi/pkg/metadata/peer"

import (
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/metadata/peer/metadatapb"
)

func snapshotToProto(snapshot *Snapshot) *metadatapb.Snapshot {
	message := &metadatapb.Snapshot{
		Hostname:          snapshot.Hostname,
		Callers:           callersToProto(snapshot.Callers),
		KnownCallers:      callersToProto(snapshot.KnownCallers),
		CallerAmbiguityMs: snapshot.CallerAmbiguityMillis,
	}

	for _, service := range snapshot.Services {
		message.Services = append(message.Services, serviceToProto(service))
	}

	for _, listener := range snapshot.Listeners {
		message.Listeners = append(message.Listeners, &metadatapb.Listener{
			Endpoint: endpointToProto(listener.Endpoint),
			Service:  serviceToProto(listener.Service),
		})
	}

	if snapshot.MetricProtocols != nil {
		protocols := uint64(*snapshot.MetricProtocols)
		message.MetricProtocols = &protocols
	}

	return message
}

// snapshotFromProto converts a message into a Snapshot that still needs validateSnapshot.
func snapshotFromProto(message *metadatapb.Snapshot) Snapshot {
	snapshot := Snapshot{
		Hostname:              message.GetHostname(),
		Callers:               callersFromProto(message.GetCallers()),
		KnownCallers:          callersFromProto(message.GetKnownCallers()),
		CallerAmbiguityMillis: message.GetCallerAmbiguityMs(),
	}

	for _, service := range message.GetServices() {
		snapshot.Services = append(snapshot.Services, serviceFromProto(service))
	}

	for _, listener := range message.GetListeners() {
		snapshot.Listeners = append(snapshot.Listeners, Listener{
			Endpoint: endpointFromProto(listener.GetEndpoint()),
			Service:  serviceFromProto(listener.GetService()),
		})
	}

	if message != nil && message.MetricProtocols != nil {
		protocols := instrumentations.InstrumentationSelection(message.GetMetricProtocols())
		snapshot.MetricProtocols = &protocols
	}

	return snapshot
}

func serviceToProto(service Service) *metadatapb.Service {
	return &metadatapb.Service{Name: service.Name, Namespace: service.Namespace, ServiceGraph: service.ServiceGraph}
}

func serviceFromProto(message *metadatapb.Service) Service {
	return Service{Name: message.GetName(), Namespace: message.GetNamespace(), ServiceGraph: message.GetServiceGraph()}
}

func endpointToProto(endpoint Endpoint) *metadatapb.Endpoint {
	return &metadatapb.Endpoint{Ip: endpoint.IP, Port: uint32(endpoint.Port)}
}

func endpointFromProto(message *metadatapb.Endpoint) Endpoint {
	return Endpoint{IP: message.GetIp(), Port: int(message.GetPort())}
}

func callersToProto(callers []Caller) []*metadatapb.Caller {
	var messages []*metadatapb.Caller
	for _, caller := range callers {
		message := &metadatapb.Caller{Destination: endpointToProto(caller.Destination)}
		for _, service := range caller.Services {
			message.Services = append(message.Services, &metadatapb.CallerService{
				Service:     serviceToProto(service.Service),
				RemainingMs: service.RemainingMillis,
			})
		}
		messages = append(messages, message)
	}

	return messages
}

func callersFromProto(messages []*metadatapb.Caller) []Caller {
	var callers []Caller
	for _, message := range messages {
		caller := Caller{Destination: endpointFromProto(message.GetDestination())}
		for _, service := range message.GetServices() {
			caller.Services = append(caller.Services, CallerService{
				Service:         serviceFromProto(service.GetService()),
				RemainingMillis: service.GetRemainingMs(),
			})
		}
		callers = append(callers, caller)
	}

	return callers
}
