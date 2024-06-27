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
	"github.com/mariomac/pipes/pipe"

	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/kube"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/transform"
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
)

const alreadyLoggedIPsCacheLen = 256

func log() *slog.Logger { return slog.With("component", "k8s.MetadataDecorator") }

func MetadataDecoratorProvider(
	ctx context.Context,
	cfg *transform.KubernetesDecorator,
	k8sInformer *kube.MetadataProvider,
) (pipe.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
	if !k8sInformer.IsKubeEnabled() {
		// This node is not going to be instantiated. Let the pipes library just bypassing it.
		return pipe.Bypass[[]*ebpf.Record](), nil
	}
	metadata, err := k8sInformer.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("instantiating k8s.MetadataDecorator: %w", err)
	}
	nt, err := newDecorator(ctx, cfg, metadata)
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
	return func(in <-chan []*ebpf.Record, out chan<- []*ebpf.Record) {
		log().Debug("starting network transformation loop")
		for flows := range in {
			out <- decorate(flows)
		}
		log().Debug("stopping network transformation loop")
	}, nil
}

type decorator struct {
	log              *slog.Logger
	alreadyLoggedIPs *simplelru.LRU[string, struct{}]
	kube             *kube.Metadata
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
	ipinfo, meta, ok := n.kube.GetInfo(ip)
	if !ok {
		if n.log.Enabled(context.TODO(), slog.LevelDebug) {
			// avoid spoofing the debug logs with the same message for each flow whose IP can't be decorated
			if !n.alreadyLoggedIPs.Contains(ip) {
				n.alreadyLoggedIPs.Add(ip, struct{}{})
				n.log.Debug("Can't find kubernetes info for IP", "ip", ip)
			}
		}
		return false
	}
	flow.Attrs.Metadata[attr.Name(prefix+attrSuffixNs)] = meta.Namespace
	flow.Attrs.Metadata[attr.Name(prefix+attrSuffixName)] = meta.Name
	flow.Attrs.Metadata[attr.Name(prefix+attrSuffixType)] = ipinfo.Kind
	flow.Attrs.Metadata[attr.Name(prefix+attrSuffixOwnerName)] = ipinfo.Owner.Name
	flow.Attrs.Metadata[attr.Name(prefix+attrSuffixOwnerType)] = ipinfo.Owner.Kind
	if ipinfo.HostIP != "" {
		flow.Attrs.Metadata[attr.Name(prefix+attrSuffixHostIP)] = ipinfo.HostIP
		if ipinfo.HostName != "" {
			flow.Attrs.Metadata[attr.Name(prefix+attrSuffixHostName)] = ipinfo.HostName
		}
	}
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

// newDecorator create a new transform
func newDecorator(ctx context.Context, cfg *transform.KubernetesDecorator, meta *kube.Metadata) (*decorator, error) {
	nt := decorator{
		log:         log(),
		clusterName: transform.KubeClusterName(ctx, cfg),
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
