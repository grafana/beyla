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

	"go.opentelemetry.io/obi/pkg/components/kube"
	"go.opentelemetry.io/obi/pkg/components/netolly/ebpf"
	"go.opentelemetry.io/obi/pkg/kubecache/informer"
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

type decorator struct {
	log              *slog.Logger
	alreadyLoggedIPs *simplelru.LRU[string, struct{}]
	kube             *kube.Store
	clusterName      string
}

type Decorator struct {
	decorator    *decorator
	Enabled      bool
	DropExternal bool
}

func NewDecorator(ctx context.Context, cfg *transform.KubernetesDecorator,
	k8sInformer *kube.MetadataProvider,
) (*Decorator, error) {
	d := &Decorator{
		Enabled:      k8sInformer.IsKubeEnabled(),
		DropExternal: cfg.DropExternal,
	}

	if !d.Enabled {
		return d, nil
	}

	nt, err := newDecorator(ctx, cfg, k8sInformer)
	if err != nil {
		return nil, fmt.Errorf("instantiating k8s.MetadataDecorator: %w", err)
	}

	d.decorator = nt

	return d, nil
}

func (d *Decorator) Decorate(r *ebpf.Record) bool {
	if !d.Enabled {
		return true
	}

	if d.DropExternal {
		return d.decorator.decorateMightDrop(r)
	}

	return d.decorator.decorateNoDrop(r)
}

func (n *decorator) decorateNoDrop(flow *ebpf.Record) bool {
	n.transform(flow)
	return true
}

func (n *decorator) decorateMightDrop(flow *ebpf.Record) bool {
	return n.transform(flow)
}

func (n *decorator) transform(flow *ebpf.Record) bool {
	if n.clusterName != "" {
		flow.Attrs.K8sClusterName = n.clusterName
	}
	srcOk := n.decorate(&flow.Attrs.Src, flow.SrcIP().IP().String())
	dstOk := n.decorate(&flow.Attrs.Dst, flow.DstIP().IP().String())
	return srcOk && dstOk
}

// decorate the flow with Kube metadata. Returns false if there is no metadata found for such IP
func (n *decorator) decorate(attrs *ebpf.InnerAttrs, ip string) bool {
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
	if owner := kube.TopOwner(meta.Pod); owner != nil {
		ownerName, ownerKind = owner.Name, owner.Kind
	}

	attrs.Namespace = meta.Namespace
	attrs.Name = meta.Name
	attrs.Type = meta.Kind
	attrs.OwnerName = ownerName
	attrs.OwnerType = ownerKind

	n.nodeLabels(attrs, meta)

	if attrs.TargetName == "" {
		attrs.TargetName = meta.Name
	}

	return true
}

func (n *decorator) nodeLabels(attrs *ebpf.InnerAttrs, meta *informer.ObjectMeta) {
	var nodeLabels map[string]string
	// add any other ownership label (they might be several, e.g. replicaset and deployment)
	if meta.Pod != nil && meta.Pod.HostIp != "" {
		attrs.NodeIP = meta.Pod.HostIp
		if host := n.kube.ObjectMetaByIP(meta.Pod.HostIp); host != nil {
			attrs.NodeName = host.Meta.Name
			nodeLabels = host.Meta.Labels
		}
	} else if meta.Kind == "Node" {
		nodeLabels = meta.Labels
	}
	if nodeLabels != nil {
		// this isn't strictly a Kubernetes attribute, but in Kubernetes
		// clusters this information is inferred from Node annotations
		if zone, ok := nodeLabels[cloudZoneLabel]; ok {
			attrs.TargetZone = zone
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
