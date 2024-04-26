package attributes

import (
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/attributes/attr"
)

type EnabledGroups int

const (
	EnableKubernetes = EnabledGroups(1 << iota)
	EnablePrometheus
	EnableHTTPRoutes
	EnablePeerInfo // TODO Beyla 2.0: remove when we remove ReportPeerInfo configuration option
	EnableTarget   // TODO Beyla 2.0: remove when we remove ReportTarget configuration option
)

func (e *EnabledGroups) Has(groups EnabledGroups) bool {
	return *e&groups != 0
}

func (e *EnabledGroups) Add(groups EnabledGroups) {
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

	var httpRoutes = Definition{
		Disabled: !groups.Has(EnableHTTPRoutes),
		Attributes: map[string]Default{
			string(semconv.HTTPRouteKey): true,
		},
	}

	var serverInfo = Definition{
		Attributes: map[string]Default{
			string(attr.ClientAddrKey): false,
		},
	}
	var httpClientInfo = Definition{
		Attributes: map[string]Default{
			string(attr.ServerAddrKey): false,
			string(attr.ServerPortKey): false,
		},
	}
	var grpcClientInfo = Definition{
		Attributes: map[string]Default{
			string(attr.ServerAddrKey): false,
		},
	}

	// the following definitions are duplicated as non-default httpServerInfo, httpClientInfo, etc...,
	// because they can be enabled by two ways. From the legacy, deprecated report_peer or report_target
	// config options, or from attributes.select
	// TODO Beyla 2.0 remove
	var deprecatedServerPeerInfo = Definition{
		Disabled: !groups.Has(EnablePeerInfo),
		Attributes: map[string]Default{
			string(attr.ClientAddrKey): true,
		},
	}
	// TODO Beyla 2.0 remove
	var deprecatedHTTPClientPeerInfo = Definition{
		Disabled: !groups.Has(EnablePeerInfo),
		Attributes: map[string]Default{
			string(attr.ServerAddrKey): true,
			string(attr.ServerPortKey): true,
		},
	}
	// TODO Beyla 2.0 remove
	var deprecatedGRPCClientPeerInfo = Definition{
		Disabled: !groups.Has(EnablePeerInfo),
		Attributes: map[string]Default{
			string(attr.ServerAddrKey): true,
		},
	}
	// TODO Beyla 2.0 remove
	var deprecatedHTTPPath = Definition{
		Disabled: !groups.Has(EnableTarget),
		Attributes: map[string]Default{
			string(attr.HTTPUrlPathKey): true,
		},
	}

	var httpCommon = Definition{
		Parents: []*Definition{&httpRoutes, &deprecatedHTTPPath},
		Attributes: map[string]Default{
			string(attr.HTTPRequestMethodKey):      true,
			string(attr.HTTPResponseStatusCodeKey): true,
			string(attr.HTTPUrlPathKey):            false,
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
			Parents: []*Definition{&appCommon, &appKubeAttributes, &httpCommon, &serverInfo, &deprecatedServerPeerInfo},
		},
		attr.SectionHTTPServerRequestSize: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &httpCommon, &serverInfo, &deprecatedServerPeerInfo},
		},
		attr.SectionHTTPClientDuration: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &httpCommon, &httpClientInfo, &deprecatedHTTPClientPeerInfo},
		},
		attr.SectionHTTPClientRequestSize: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &httpCommon, &httpClientInfo, &deprecatedHTTPClientPeerInfo},
		},
		attr.SectionRPCClientDuration: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &grpcClientInfo, &deprecatedGRPCClientPeerInfo},
			Attributes: map[string]Default{
				string(semconv.RPCMethodKey):         true,
				string(semconv.RPCSystemKey):         true,
				string(semconv.RPCGRPCStatusCodeKey): true,
				string(attr.ServerAddrKey):           true,
			},
		},
		attr.SectionRPCServerDuration: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &serverInfo, &deprecatedServerPeerInfo},
			Attributes: map[string]Default{
				string(semconv.RPCMethodKey):         true,
				string(semconv.RPCSystemKey):         true,
				string(semconv.RPCGRPCStatusCodeKey): true,
				string(attr.ClientAddrKey):           true,
			},
		},
		attr.SectionSQLClientDuration: {
			Parents: []*Definition{&appCommon, &appKubeAttributes},
			Attributes: map[string]Default{
				string(semconv.DBOperationKey): true,
			},
		},
	}
}
