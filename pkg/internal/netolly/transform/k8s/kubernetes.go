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
	"fmt"
	"log/slog"

	"github.com/mariomac/pipes/pkg/node"

	"github.com/grafana/beyla/pkg/beyla"
	"github.com/grafana/beyla/pkg/internal/netolly/ebpf"
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

func log() *slog.Logger { return slog.With("component", "transform.NetworkTransform") }

type NetworkTransformConfig struct {
	TransformConfig *beyla.NetworkTransformConfig
}

func NetworkTransform(cfg NetworkTransformConfig) (node.MiddleFunc[[]*ebpf.Record, []*ebpf.Record], error) {
	nt, err := newTransformNetwork(cfg.TransformConfig)
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
	kube NetworkInformers
	cfg  *beyla.NetworkTransformConfig
}

func (n *networkTransformer) transform(flow *ebpf.Record) {
	if flow.Metadata == nil {
		flow.Metadata = map[string]string{}
	}
	n.decorate(flow, attrPrefixSrc, flow.Id.SrcIP().IP().String())
	n.decorate(flow, attrPrefixDst, flow.Id.DstIP().IP().String())

}

func (n *networkTransformer) decorate(flow *ebpf.Record, prefix, ip string) {
	kubeInfo, err := n.kube.GetInfo(ip)
	if err != nil {
		log().Debug("Can't find kubernetes info for IP", "ip", ip, "error", err)
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
func newTransformNetwork(cfg *beyla.NetworkTransformConfig) (*networkTransformer, error) {
	nt := networkTransformer{cfg: cfg}

	if err := nt.kube.InitFromConfig(cfg.KubeConfigPath); err != nil {
		return nil, err
	}
	return &nt, nil
}
