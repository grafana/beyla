package metric

import (
	semconv "go.opentelemetry.io/otel/semconv/v1.19.0"

	"github.com/grafana/beyla/pkg/internal/export/metric/attr"
)

type EnabledGroups int

const (
	EnableKubernetes = EnabledGroups(1 << iota)
	EnablePrometheus
	EnableHTTPRoutes
	EnableIfaceDirection
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
func getDefinitions(groups EnabledGroups) map[Section]Definition {
	kubeEnabled := groups.Has(EnableKubernetes)
	promEnabled := groups.Has(EnablePrometheus)
	ifaceDirEnabled := groups.Has(EnableIfaceDirection)
	peerInfoEnabled := groups.Has(EnablePeerInfo)

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
			string(attr.ClientAddrKey): Default(peerInfoEnabled),
		},
	}
	var httpClientInfo = Definition{
		Attributes: map[string]Default{
			string(attr.ServerAddrKey): Default(peerInfoEnabled),
			string(attr.ServerPortKey): Default(peerInfoEnabled),
		},
	}
	var grpcClientInfo = Definition{
		Attributes: map[string]Default{
			string(attr.ServerAddrKey): Default(peerInfoEnabled),
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

	return map[Section]Definition{
		BeylaNetworkFlow.Section: {
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
				attr.Direction:  Default(ifaceDirEnabled),
				attr.Iface:      Default(ifaceDirEnabled),
			},
		},
		HTTPServerDuration.Section: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &httpCommon, &serverInfo},
		},
		HTTPServerRequestSize.Section: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &httpCommon, &serverInfo},
		},
		HTTPClientDuration.Section: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &httpCommon, &httpClientInfo},
		},
		HTTPClientRequestSize.Section: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &httpCommon, &httpClientInfo},
		},
		RPCClientDuration.Section: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &grpcClientInfo},
			Attributes: map[string]Default{
				string(semconv.RPCMethodKey):         true,
				string(semconv.RPCSystemKey):         true,
				string(semconv.RPCGRPCStatusCodeKey): true,
			},
		},
		RPCServerDuration.Section: {
			Parents: []*Definition{&appCommon, &appKubeAttributes, &serverInfo},
			Attributes: map[string]Default{
				string(semconv.RPCMethodKey):         true,
				string(semconv.RPCSystemKey):         true,
				string(semconv.RPCGRPCStatusCodeKey): true,
				// Overriding default serverInfo configuration because we want
				// to report it by default
				string(attr.ClientAddrKey): true,
			},
		},
		SQLClientDuration.Section: {
			Parents: []*Definition{&appCommon, &appKubeAttributes},
			Attributes: map[string]Default{
				string(semconv.DBOperationKey): true,
			},
		},
	}
}
