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
	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/pkg/internal/transform"
)

const (
	attrPrefixSrc       = "k8s.src"
	attrPrefixDst       = "k8s.dst"
	attrSuffixNs        = ".namespace"
	attrSuffixName      = ".name"
	attrSuffixType      = ".type"
	attrSuffixOwnerName = ".owner.name"
	attrSuffixOwnerType = ".owner.type"
	attrSuffixHostIP    = ".host.ip"
	attrSuffixHostName  = ".host.name"

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

func log() *slog.Logger { return slog.With("component", "transform.NetworkTransform") }

type NetworkTransformConfig struct {
	Kubernetes *transform.KubernetesDecorator
}

func NetworkTransform(cfg NetworkTransformConfig) (node.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
	nt, err := newTransformNetwork(&cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiating network transformer: %w", err)
	}
	return func(in <-chan []*ebpf.Record, out chan<- []*ebpf.Record) {
		log().Debug("starting network transformation loop")
		for flows := range in {
			for _, flow := range flows {
				nt.transform(flow)
			}
			out <- flows
		}
		log().Debug("stopping network transformation loop")
	}, nil
}

type networkTransformer struct {
	log              *slog.Logger
	alreadyLoggedIPs *simplelru.LRU[string, struct{}]
	kube             NetworkInformers
}

func (n *networkTransformer) transform(flow *ebpf.Record) {
	if flow.Metadata == nil {
		flow.Metadata = map[string]string{}
	}
	n.decorate(flow, attrPrefixSrc, flow.Id.SrcIP().IP().String())
	n.decorate(flow, attrPrefixDst, flow.Id.DstIP().IP().String())

}

func (n *networkTransformer) decorate(flow *ebpf.Record, prefix, ip string) {
	kubeInfo, ok := n.kube.GetInfo(ip)
	if !ok {
		if n.log.Enabled(context.TODO(), slog.LevelDebug) {
			// avoid spoofing the debug logs with the same message for each flow whose IP can't be decorated
			if !n.alreadyLoggedIPs.Contains(ip) {
				n.alreadyLoggedIPs.Add(ip, struct{}{})
				n.log.Debug("Can't find kubernetes info for IP", "ip", ip)
			}
		}
		return
	}
	flow.Metadata[prefix+attrSuffixNs] = kubeInfo.Namespace
	flow.Metadata[prefix+attrSuffixName] = kubeInfo.Name
	flow.Metadata[prefix+attrSuffixType] = kubeInfo.Type
	flow.Metadata[prefix+attrSuffixOwnerName] = kubeInfo.Owner.Name
	flow.Metadata[prefix+attrSuffixOwnerType] = kubeInfo.Owner.Type
	if kubeInfo.HostIP != "" {
		flow.Metadata[prefix+attrSuffixHostIP] = kubeInfo.HostIP
		if kubeInfo.HostName != "" {
			flow.Metadata[prefix+attrSuffixHostName] = kubeInfo.HostName
		}
	}
}

// newTransformNetwork create a new transform
func newTransformNetwork(cfg *NetworkTransformConfig) (*networkTransformer, error) {
	nt := networkTransformer{log: log()}
	if nt.log.Enabled(context.TODO(), slog.LevelDebug) {
		var err error
		nt.alreadyLoggedIPs, err = simplelru.NewLRU[string, struct{}](alreadyLoggedIPsCacheLen, nil)
		if err != nil {
			return nil, fmt.Errorf("instantiating debug notified error cache: %w")
		}
	}

	if err := nt.kube.InitFromConfig(cfg.Kubernetes.KubeconfigPath, cfg.Kubernetes.InformersSyncTimeout); err != nil {
		return nil, err
	}
	return &nt, nil
}
