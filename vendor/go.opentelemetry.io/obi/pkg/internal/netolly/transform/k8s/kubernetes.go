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

package k8s

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	ikube "go.opentelemetry.io/obi/pkg/internal/kube"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
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

func MetadataDecoratorProvider(
	ctx context.Context,
	cfg *transform.KubernetesDecorator,
	k8sInformer *kube.MetadataProvider,
	input, output *msg.Queue[[]*ebpf.Record],
) swarm.InstanceFunc {
	return func(_ context.Context) (swarm.RunFunc, error) {
		if !k8sInformer.IsKubeEnabled() {
			return swarm.Bypass(input, output)
		}
		nt, err := newDecorator(ctx, cfg, k8sInformer)
		if err != nil {
			return nil, fmt.Errorf("instantiating k8s.MetadataDecorator: %w", err)
		}
		var decorate func([]*ebpf.Record) []*ebpf.Record
		if cfg.DropExternal {
			log().Debug("will drop external flows")
			decorate = nt.decorateMightDrop
		} else {
			decorate = nt.decorateNoDrop
		}
		in := input.Subscribe(msg.SubscriberName("k8s.MetadataDecorator"))
		return func(ctx context.Context) {
			defer output.Close()
			swarms.ForEachInput(ctx, in, log().Debug, func(flows []*ebpf.Record) {
				output.Send(decorate(flows))
			})
		}, nil
	}
}

type decorator struct {
	log              *slog.Logger
	alreadyLoggedIPs *simplelru.LRU[string, struct{}]
	kube             *kube.Store
	clusterName      string
}

func (n *decorator) decorateNoDrop(flows []*ebpf.Record) []*ebpf.Record {
	for _, flow := range flows {
		n.transform(flow)
	}
	return flows
}

func (n *decorator) decorateMightDrop(flows []*ebpf.Record) []*ebpf.Record {
	out := make([]*ebpf.Record, 0, len(flows))
	for _, flow := range flows {
		if n.transform(flow) {
			out = append(out, flow)
		}
	}
	return out
}

func (n *decorator) transform(flow *ebpf.Record) bool {
	if flow.Attrs.Metadata == nil {
		flow.Attrs.Metadata = map[attr.Name]string{}
	}
	if n.clusterName != "" {
		flow.Attrs.Metadata[(attr.K8sClusterName)] = n.clusterName
	}
	srcOk := n.decorate(flow, attrPrefixSrc, flow.Id.SrcIP().IP().String())
	dstOk := n.decorate(flow, attrPrefixDst, flow.Id.DstIP().IP().String())
	return srcOk && dstOk
}

// decorate the flow with Kube metadata. Returns false if there is no metadata found for such IP
func (n *decorator) decorate(flow *ebpf.Record, prefix, ip string) bool {
	cachedObj := n.kube.ObjectMetaByIP(ip)
	if cachedObj == nil {
		if n.log.Enabled(context.TODO(), slog.LevelDebug) {
			// avoid spoofing the debug logs with the same message for each flow whose IP can't be decorated
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

	flow.Attrs.Metadata[attr.Name(prefix+attrSuffixNs)] = meta.Namespace
	flow.Attrs.Metadata[attr.Name(prefix+attrSuffixName)] = meta.Name
	flow.Attrs.Metadata[attr.Name(prefix+attrSuffixType)] = meta.Kind
	flow.Attrs.Metadata[attr.Name(prefix+attrSuffixOwnerName)] = ownerName
	flow.Attrs.Metadata[attr.Name(prefix+attrSuffixOwnerType)] = ownerKind

	n.nodeLabels(flow, prefix, meta)

	// decorate other names from metadata, if required
	if prefix == attrPrefixDst {
		if flow.Attrs.DstName == "" {
			flow.Attrs.DstName = meta.Name
		}
	} else {
		if flow.Attrs.SrcName == "" {
			flow.Attrs.SrcName = meta.Name
		}
	}
	return true
}

func (n *decorator) nodeLabels(flow *ebpf.Record, prefix string, meta *informer.ObjectMeta) {
	var nodeLabels map[string]string
	// add any other ownership label (they might be several, e.g. replicaset and deployment)
	if meta.Pod != nil && meta.Pod.HostIp != "" {
		flow.Attrs.Metadata[attr.Name(prefix+attrSuffixHostIP)] = meta.Pod.HostIp
		if host := n.kube.ObjectMetaByIP(meta.Pod.HostIp); host != nil {
			flow.Attrs.Metadata[attr.Name(prefix+attrSuffixHostName)] = host.Meta.Name
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
				flow.Attrs.DstZone = zone
			} else {
				flow.Attrs.SrcZone = zone
			}
		}
	}
}

// newDecorator create a new transform
func newDecorator(ctx context.Context, cfg *transform.KubernetesDecorator, k8sInformer *kube.MetadataProvider) (*decorator, error) {
	meta, err := k8sInformer.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("instantiating k8s.MetadataDecorator: %w", err)
	}
	nt := decorator{
		log:         log(),
		clusterName: transform.KubeClusterName(ctx, cfg, k8sInformer),
		kube:        meta,
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
