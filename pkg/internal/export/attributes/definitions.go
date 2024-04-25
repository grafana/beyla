package attributes

import (
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/attributes/attr"
)

type EnabledGroups int

const (
	EnableKubernetes = EnabledGroups(1)
	EnablePrometheus = EnabledGroups(2)
)

func (e *EnabledGroups) Has(groups EnabledGroups) bool {
	return *e&groups != 0
}

func (e *EnabledGroups) Set(groups EnabledGroups) {
	*e |= groups
}

// Any new metric and attribute must be added here so the selectors will make their
func getDefinitions(groups EnabledGroups) map[attr.Section]Definition {
	kubeEnabled := groups.Has(EnableKubernetes)
	promEnabled := groups.Has(EnablePrometheus)

	var prometheusAttributes = Definition{
		Disabled: !promEnabled,
		Attributes: map[string]Default{
			attr.TargetInstanceKey: true,
		},
	}

	var networkKubeAttributes = Definition{
		Disabled: !kubeEnabled,
		Attributes: map[string]Default{
			attr.K8sSrcOwnerName: true,
			attr.K8sSrcNamespace: true,
			attr.K8sDstOwnerName: true,
			attr.K8sDstNamespace: true,
			attr.K8sClusterName:  true,
			attr.K8sSrcName:      false,
			attr.K8sSrcType:      false,
			attr.K8sSrcOwnerType: false,
			attr.K8sSrcNodeIP:    false,
			attr.K8sSrcNodeName:  false,
			attr.K8sDstName:      false,
			attr.K8sDstType:      false,
			attr.K8sDstOwnerType: false,
			attr.K8sDstNodeIP:    false,
			attr.K8sDstNodeName:  false,
		},
	}

	var appKubeAttributes = Definition{
		Disabled: !kubeEnabled,
		Attributes: map[string]Default{
			attr.K8sNamespaceName:   true,
			attr.K8sPodName:         true,
			attr.K8sDeploymentName:  true,
			attr.K8sReplicaSetName:  true,
			attr.K8sDaemonSetName:   true,
			attr.K8sStatefulSetName: true,
			attr.K8sNodeName:        true,
			attr.K8sPodUID:          true,
			attr.K8sPodStartTime:    true,
		},
	}

	var appCommon = Definition{
		Parents: []*Definition{&prometheusAttributes},
		Attributes: map[string]Default{
			string(semconv.ServiceNameKey): true,
		},
	}

	var appHTTPDuration = Definition{
		Attributes: map[string]Default{
			string(attr.HTTPRequestMethodKey):      true,
			string(attr.HTTPResponseStatusCodeKey): true,
			string(semconv.HTTPRouteKey):           true,
			string(attr.HTTPUrlPathKey):            false,
			string(attr.ClientAddrKey):             false,
		},
	}

	return map[attr.Section]Definition{
		attr.SectionBeylaNetworkFlow: {
			Parents: []*Definition{&networkKubeAttributes},
			Attributes: map[string]Default{
				attr.BeylaIP:    false,
				attr.Transport:  false,
				attr.SrcAddress: false,
				attr.DstAddres:  false,
				attr.SrcPort:    false,
				attr.DstPort:    false,
				attr.SrcName:    false,
				attr.DstName:    false,
				attr.Direction:  false,
				attr.Iface:      false,
			},
		},
		attr.SectionHTTPServerDuration: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &appHTTPDuration},
		},
		attr.SectionHTTPClientDuration: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &appHTTPDuration},
		},
		attr.SectionHTTPServerRequestSize: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &appHTTPDuration},
		},
		attr.SectionHTTPClientRequestSize: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &appHTTPDuration},
		},
		attr.SectionRPCClientDuration: {
			Parents: []*Definition{&appCommon, &appKubeAttributes},
			Attributes: map[string]Default{
				string(semconv.RPCMethodKey):         true,
				string(semconv.RPCSystemKey):         true,
				string(semconv.RPCGRPCStatusCodeKey): true,
				string(attr.ServerAddrKey):           true,
			},
		},
		attr.SectionRPCServerDuration: {
			Parents: []*Definition{&appCommon, &appKubeAttributes},
			Attributes: map[string]Default{
				string(semconv.RPCMethodKey):         true,
				string(semconv.RPCSystemKey):         true,
				string(semconv.RPCGRPCStatusCodeKey): true,
				string(attr.ClientAddrKey):           true,
			},
		},
	}
}
