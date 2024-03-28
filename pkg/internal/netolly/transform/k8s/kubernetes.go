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
	"time"

	"github.com/hashicorp/golang-lru/v2/simplelru"
	"github.com/mariomac/pipes/pkg/node"

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

	AttrClusterName = "k8s.cluster.name"

	AttrDstNamespace = attrPrefixDst + attrSuffixNs
	AttrDstName      = attrPrefixDst + attrSuffixName
	AttrDstType      = attrPrefixDst + attrSuffixType
	AttrDstOwnerName = attrPrefixDst + attrSuffixOwnerName
	AttrDstOwnerType = attrPrefixDst + attrSuffixOwnerType
	AttrDstHostIP    = attrPrefixDst + attrSuffixHostIP
	AttrDstHostName  = attrPrefixDst + attrSuffixHostName

	AttrSrcNamespace = attrPrefixSrc + attrSuffixNs
	AttrSrcName      = attrPrefixSrc + attrSuffixName
	AttrSrcType      = attrPrefixSrc + attrSuffixType
	AttrSrcOwnerName = attrPrefixSrc + attrSuffixOwnerName
	AttrSrcOwnerType = attrPrefixSrc + attrSuffixOwnerType
	AttrSrcHostIP    = attrPrefixSrc + attrSuffixHostIP
	AttrSrcHostName  = attrPrefixSrc + attrSuffixHostName
)

const alreadyLoggedIPsCacheLen = 256
const (
	clusterMetadataRetries       = 5
	clusterMetadataFailRetryTime = 500 * time.Millisecond
)

func log() *slog.Logger { return slog.With("component", "k8s.MetadataDecorator") }

type MetadataDecorator struct {
	Kubernetes *transform.KubernetesDecorator
}

func (ntc MetadataDecorator) Enabled() bool {
	return ntc.Kubernetes != nil && ntc.Kubernetes.Enabled()
}

func MetadataDecoratorProvider(ctx context.Context, cfg MetadataDecorator) (node.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
	nt, err := newDecorator(ctx, &cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiating network transformer: %w", err)
	}
	var decorate func([]*ebpf.Record) []*ebpf.Record
	if cfg.Kubernetes.DropExternal {
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
	kube             NetworkInformers
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
		flow.Attrs.Metadata = map[string]string{}
	}
	if n.clusterName != "" {
		flow.Attrs.Metadata[AttrClusterName] = n.clusterName
	}
	srcOk := n.decorate(flow, attrPrefixSrc, flow.Id.SrcIP().IP().String())
	dstOk := n.decorate(flow, attrPrefixDst, flow.Id.DstIP().IP().String())
	return srcOk && dstOk
}

// decorate the flow with Kube metadata. Returns false if there is no metadata found for such IP
func (n *decorator) decorate(flow *ebpf.Record, prefix, ip string) bool {
	kubeInfo, ok := n.kube.GetInfo(ip)
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
	flow.Attrs.Metadata[prefix+attrSuffixNs] = kubeInfo.Namespace
	flow.Attrs.Metadata[prefix+attrSuffixName] = kubeInfo.Name
	flow.Attrs.Metadata[prefix+attrSuffixType] = kubeInfo.Type
	flow.Attrs.Metadata[prefix+attrSuffixOwnerName] = kubeInfo.Owner.Name
	flow.Attrs.Metadata[prefix+attrSuffixOwnerType] = kubeInfo.Owner.Type
	if kubeInfo.HostIP != "" {
		flow.Attrs.Metadata[prefix+attrSuffixHostIP] = kubeInfo.HostIP
		if kubeInfo.HostName != "" {
			flow.Attrs.Metadata[prefix+attrSuffixHostName] = kubeInfo.HostName
		}
	}
	// decorate other names from metadata, if required
	if prefix == attrPrefixDst {
		if flow.Attrs.DstName == "" {
			flow.Attrs.DstName = kubeInfo.Name
		}
	} else {
		if flow.Attrs.SrcName == "" {
			flow.Attrs.SrcName = kubeInfo.Name
		}
	}
	return true
}

// newDecorator create a new transform
func newDecorator(ctx context.Context, cfg *MetadataDecorator) (*decorator, error) {
	nt := decorator{
		log:         log(),
		clusterName: kubeClusterName(ctx, cfg),
	}
	if nt.log.Enabled(ctx, slog.LevelDebug) {
		var err error
		nt.alreadyLoggedIPs, err = simplelru.NewLRU[string, struct{}](alreadyLoggedIPsCacheLen, nil)
		if err != nil {
			return nil, fmt.Errorf("instantiating debug notified error cache: %w", err)
		}
	}

	if err := nt.kube.InitFromConfig(cfg.Kubernetes.KubeconfigPath, cfg.Kubernetes.InformersSyncTimeout); err != nil {
		return nil, err
	}
	return &nt, nil
}

func kubeClusterName(ctx context.Context, cfg *MetadataDecorator) string {
	log := log().With("func", "kubeClusterName")
	if cfg.Kubernetes.ClusterName != "" {
		return cfg.Kubernetes.ClusterName
	}
	retries := 0
	for retries < clusterMetadataRetries {
		if clusterName := fetchClusterName(ctx); clusterName != "" {
			return clusterName
		}
		retries++
		log.Debug("retrying cluster name fetching in 500 ms...")
		select {
		case <-ctx.Done():
			log.Debug("context canceled before starting the kubernetes decorator node")
			return ""
		case <-time.After(clusterMetadataFailRetryTime):
			// retry or end!
		}
	}
	log.Warn("can't fetch Kubernetes Cluster Name." +
		" Network metrics won't contain k8s.cluster.name attribute unless you explicitly set " +
		" the BEYLA_KUBE_CLUSTER_NAME environment variable")
	return ""
}
