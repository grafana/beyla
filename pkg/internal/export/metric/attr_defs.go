package metric

import (
	"github.com/grafana/beyla/pkg/internal/export/metric/attr"
)

// EnabledGroups will let enabling by default some groups of attributes under
// given circumstances. For example, will let enabling kubernetes metadata attributes
// only if Beyla is running under Kubernetes and kube metadata is enabled.
type EnabledGroups int

const (
	EnableKubernetes = EnabledGroups(1 << iota)
	EnablePrometheus
	EnableHTTPRoutes
	EnableNetIfaceDirection
	EnableNetCIDR
	EnablePeerInfo // TODO Beyla 2.0: remove when we remove ReportPeerInfo configuration option
	EnableTarget   // TODO Beyla 2.0: remove when we remove ReportTarget configuration option
)

func (e *EnabledGroups) Has(groups EnabledGroups) bool {
	return *e&groups != 0
}

func (e *EnabledGroups) Add(groups EnabledGroups) {
	*e |= groups
}

// Any new metric and attribute must be added here to be matched from the user-provided wildcard
// selectors of the attributes.select section
func getDefinitions(groups EnabledGroups) map[Section]Definition {
	kubeEnabled := groups.Has(EnableKubernetes)
	promEnabled := groups.Has(EnablePrometheus)
	ifaceDirEnabled := groups.Has(EnableNetIfaceDirection)
	peerInfoEnabled := groups.Has(EnablePeerInfo)
	cidrEnabled := groups.Has(EnableNetCIDR)

	// attributes to be reported exclusively for prometheus exporters
	var prometheusAttributes = Definition{
		Disabled: !promEnabled,
		Attributes: map[attr.Name]Default{
			attr.TargetInstance: true,
			attr.ServiceName:    true,
		},
	}

	// attributes to be reported exclusively for network metrics when
	// kubernetes metadata is enabled
	var networkKubeAttributes = Definition{
		Disabled: !kubeEnabled,
		Attributes: map[attr.Name]Default{
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

	// network CIDR attributes are only enabled if the CIDRs configuration
	// is defined
	var networkCIDR = Definition{
		Disabled: !cidrEnabled,
		Attributes: map[attr.Name]Default{
			attr.DstCIDR: true,
			attr.SrcCIDR: true,
		},
	}

	// attributes to be reported exclusively for application metrics when
	// kubernetes metadata is enabled
	var appKubeAttributes = Definition{
		Disabled: !kubeEnabled,
		Attributes: map[attr.Name]Default{
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

	var httpRoutes = Definition{
		Disabled: !groups.Has(EnableHTTPRoutes),
		Attributes: map[attr.Name]Default{
			attr.HTTPRoute: true,
		},
	}

	var serverInfo = Definition{
		Attributes: map[attr.Name]Default{
			attr.ClientAddr: Default(peerInfoEnabled),
		},
	}
	var httpClientInfo = Definition{
		Attributes: map[attr.Name]Default{
			attr.ServerAddr: Default(peerInfoEnabled),
			attr.ServerPort: Default(peerInfoEnabled),
		},
	}
	var grpcClientInfo = Definition{
		Attributes: map[attr.Name]Default{
			attr.ServerAddr: Default(peerInfoEnabled),
		},
	}

	// TODO Beyla 2.0 remove
	// this just defaults the path as default when the target report is enabled
	// via the deprecated BEYLA_METRICS_REPORT_PEER config option
	var deprecatedHTTPPath = Definition{
		Disabled: !groups.Has(EnableTarget),
		Attributes: map[attr.Name]Default{
			attr.HTTPUrlPath: true,
		},
	}

	var httpCommon = Definition{
		Parents: []*Definition{&httpRoutes, &deprecatedHTTPPath},
		Attributes: map[attr.Name]Default{
			attr.HTTPRequestMethod:      true,
			attr.HTTPResponseStatusCode: true,
			attr.HTTPUrlPath:            false,
		},
	}

	return map[Section]Definition{
		BeylaNetworkFlow.Section: {
			Parents: []*Definition{&networkCIDR, &networkKubeAttributes},
			Attributes: map[attr.Name]Default{
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
			Parents: []*Definition{&prometheusAttributes, &appKubeAttributes, &httpCommon, &serverInfo},
		},
		HTTPServerRequestSize.Section: {
			Parents: []*Definition{&prometheusAttributes, &appKubeAttributes, &httpCommon, &serverInfo},
		},
		HTTPClientDuration.Section: {
			Parents: []*Definition{&prometheusAttributes, &appKubeAttributes, &httpCommon, &httpClientInfo},
		},
		HTTPClientRequestSize.Section: {
			Parents: []*Definition{&prometheusAttributes, &appKubeAttributes, &httpCommon, &httpClientInfo},
		},
		RPCClientDuration.Section: {
			Parents: []*Definition{&prometheusAttributes, &appKubeAttributes, &grpcClientInfo},
			Attributes: map[attr.Name]Default{
				attr.RPCMethod:         true,
				attr.RPCSystem:         true,
				attr.RPCGRPCStatusCode: true,
			},
		},
		RPCServerDuration.Section: {
			Parents: []*Definition{&prometheusAttributes, &appKubeAttributes, &serverInfo},
			Attributes: map[attr.Name]Default{
				attr.RPCMethod:         true,
				attr.RPCSystem:         true,
				attr.RPCGRPCStatusCode: true,
				// Overriding default serverInfo configuration because we want
				// to report it by default
				attr.ClientAddr: true,
			},
		},
		SQLClientDuration.Section: {
			Parents: []*Definition{&prometheusAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]Default{
				attr.DBOperation: true,
			},
		},
	}
}
