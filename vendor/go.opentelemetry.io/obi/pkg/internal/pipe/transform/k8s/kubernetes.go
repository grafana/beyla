// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package k8s // import "go.opentelemetry.io/obi/pkg/internal/pipe/transform/k8s"

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/pipe"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/kube/kubecache/informer"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/transform"
)

const (
	attrPrefixSrc       = "k8s.src"
	attrPrefixDst       = "k8s.dst"
	attrSuffixNs        = ".namespace"
	attrSuffixName      = ".name"
	attrSuffixType      = ".type"
	attrSuffixOwnerName = ".owner.name"
	attrSuffixOwnerType = ".owner.type"
	attrSuffixHostIP    = ".node.ip"
	attrSuffixHostName  = ".node.name"

	cloudZoneLabel = "topology.kubernetes.io/zone"
)

const alreadyLoggedIPsCacheLen = 256

func log() *slog.Logger { return slog.With("component", "k8s.MetadataDecorator") }

func MetadataDecoratorProvider[T any](
	ctx context.Context,
	cfg *transform.KubernetesDecorator,
	k8sInformer *kube.MetadataProvider,
	attrs func(T) *pipe.CommonAttrs,
	input, output *msg.Queue[[]T],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !k8sInformer.IsKubeEnabled() {
			return swarm.Bypass(input, output)
		}
		nt, err := newDecorator(ctx, cfg, k8sInformer)
		if err != nil {
			return nil, fmt.Errorf("instantiating k8s.MetadataDecorator: %w", err)
		}
		if cfg.DropExternal {
			log().Debug("will drop external items")
		}
		in := input.Subscribe(msg.SubscriberName("k8s.MetadataDecorator"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, log().Debug, func(items []T) {
				if cfg.DropExternal {
					out := make([]T, 0, len(items))
					for _, item := range items {
						if nt.transform(attrs(item)) {
							out = append(out, item)
						}
					}
					output.Send(out)
				} else {
					for _, item := range items {
						nt.transform(attrs(item))
					}
					output.Send(items)
				}
			})
		}, nil
	}
}

type decorator struct {
	log              *slog.Logger
	alreadyLoggedIPs *simplelru.LRU[string, struct{}]
	store            *kube.Store
	clusterName      string
}

func (n *decorator) transform(a *pipe.CommonAttrs) bool {
	if a.Metadata == nil {
		a.Metadata = map[attr.Name]string{}
	}
	if n.clusterName != "" {
		a.Metadata[(attr.K8sClusterName)] = n.clusterName
	}
	srcOk := n.decorate(a, attrPrefixSrc, a.SrcAddr.IP().String())
	dstOk := n.decorate(a, attrPrefixDst, a.DstAddr.IP().String())
	return srcOk && dstOk
}

// decorate the item with Kube metadata. Returns false if there is no metadata found for such IP
func (n *decorator) decorate(a *pipe.CommonAttrs, prefix, ip string) bool {
	cachedObj := n.store.ObjectMetaByIP(ip)
	if cachedObj == nil {
		if n.log.Enabled(context.TODO(), slog.LevelDebug) {
			// avoid spoofing the debug logs with the same message for each item whose IP can't be decorated
			if !n.alreadyLoggedIPs.Contains(ip) {
				n.alreadyLoggedIPs.Add(ip, struct{}{})
				n.log.Debug("Can't find kubernetes info for IP", "ip", ip)
			}
		}
		return false
	}
	meta := cachedObj.Meta
	ownerName, ownerKind := meta.Name, meta.Kind
	if owner := ikube.TopOwner(meta.Pod); owner != nil {
		ownerName, ownerKind = owner.Name, owner.Kind
	}

	a.Metadata[attr.Name(prefix+attrSuffixNs)] = meta.Namespace
	a.Metadata[attr.Name(prefix+attrSuffixName)] = meta.Name
	a.Metadata[attr.Name(prefix+attrSuffixType)] = meta.Kind
	a.Metadata[attr.Name(prefix+attrSuffixOwnerName)] = ownerName
	a.Metadata[attr.Name(prefix+attrSuffixOwnerType)] = ownerKind

	// Only resolve service name/namespace for Pods. Nodes and other non-pod
	// objects don't represent services and would incorrectly use the object name.
	if meta.Pod != nil {
		serviceName, serviceNamespace, _ := n.store.ServiceNameNamespaceForIP(ip)
		if prefix == attrPrefixSrc {
			a.Metadata[attr.ServiceName] = serviceName
			a.Metadata[attr.ServiceNamespace] = serviceNamespace
		} else {
			a.Metadata[attr.ServicePeerName] = serviceName
			a.Metadata[attr.ServicePeerNamespace] = serviceNamespace
		}
	}

	n.nodeLabels(a, prefix, meta)

	// decorate other names from metadata, if required
	if prefix == attrPrefixDst {
		if a.DstName == "" {
			a.DstName = meta.Name
		}
	} else {
		if a.SrcName == "" {
			a.SrcName = meta.Name
		}
	}
	return true
}

func (n *decorator) nodeLabels(a *pipe.CommonAttrs, prefix string, meta *informer.ObjectMeta) {
	var nodeLabels map[string]string
	// add any other ownership label (they might be several, e.g. replicaset and deployment)
	if meta.Pod != nil && meta.Pod.HostIp != "" {
		a.Metadata[attr.Name(prefix+attrSuffixHostIP)] = meta.Pod.HostIp
		if host := n.store.ObjectMetaByIP(meta.Pod.HostIp); host != nil {
			a.Metadata[attr.Name(prefix+attrSuffixHostName)] = host.Meta.Name
			nodeLabels = host.Meta.Labels
		}
	} else if meta.Kind == "Node" {
		nodeLabels = meta.Labels
	}
	if nodeLabels != nil {
		// this isn't strictly a Kubernetes attribute, but in Kubernetes
		// clusters this information is inferred from Node annotations
		if zone, ok := nodeLabels[cloudZoneLabel]; ok {
			if prefix == attrPrefixDst {
				a.DstZone = zone
			} else {
				a.SrcZone = zone
			}
		}
	}
}

// newDecorator create a new transform
func newDecorator(ctx context.Context, cfg *transform.KubernetesDecorator, k8sInformer *kube.MetadataProvider) (*decorator, error) {
	store, err := k8sInformer.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("instantiating k8s.MetadataDecorator: %w", err)
	}
	nt := decorator{
		log:         log(),
		clusterName: transform.KubeClusterName(ctx, cfg, k8sInformer),
		store:       store,
	}
	if nt.log.Enabled(ctx, slog.LevelDebug) {
		var err error
		nt.alreadyLoggedIPs, err = simplelru.NewLRU[string, struct{}](alreadyLoggedIPsCacheLen, nil)
		if err != nil {
			return nil, fmt.Errorf("instantiating debug notified error cache: %w", err)
		}
	}
	return &nt, nil
}
