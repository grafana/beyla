package attributes

import (
	"fmt"
	"log/slog"
	"maps"

	attrobi "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes"
	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"

	attrextra "github.com/grafana/beyla/v2/pkg/export/attributes/beyla"
)

// AttrGroups will let enabling by default some groups of attributes under
// given circumstances. For example, will let enabling kubernetes metadata attributes
// only if Beyla is running under Kubernetes and kube metadata is enabled.

const (
	UndefinedGroup         = attrobi.AttrGroups(0)
	GroupKubernetes        = attrobi.AttrGroups(1 << iota)
	GroupPrometheus        = attrobi.GroupPrometheus
	GroupHTTPRoutes        = attrobi.GroupHTTPRoutes
	GroupNetIfaceDirection = attrobi.GroupNetIfaceDirection
	GroupNetCIDR           = attrobi.GroupNetCIDR
	GroupTraces            = attrobi.GroupTraces
	GroupApp               = attrobi.GroupApp
	GroupNet               = attrobi.GroupNet
	GroupNetKube           = attrobi.GroupNetKube
	GroupAppKube           = attrobi.GroupAppKube
	GroupServerInfo        = attrobi.GroupServerInfo
	GroupHTTPClientInfo    = attrobi.GroupHTTPClientInfo
	GroupGRPCClientInfo    = attrobi.GroupGRPCClientInfo
	GroupHTTPCommon        = attrobi.GroupHTTPCommon
	GroupHost              = attrobi.GroupHost
	GroupMessaging         = attrobi.GroupMessaging
	GroupPromProcess
	GroupProcess
)

func alog() *slog.Logger {
	return slog.With("component", "attributes")
}

func newAttrReportGroup(
	disabled bool,
	subGroups []*attrobi.AttrReportGroup,
	attributes map[attr.Name]attrobi.Default,
	extraAttributes []attr.Name,
) attrobi.AttrReportGroup {
	for _, extraAttr := range extraAttributes {
		attributes[extraAttr] = true
	}

	return attrobi.AttrReportGroup{
		Disabled:   disabled,
		SubGroups:  subGroups,
		Attributes: attributes,
	}
}

func newGroupAttributes(groupAttrsCfg map[string][]attr.Name) attrobi.GroupAttributes {
	log := alog()

	groupAttrs := make(attrobi.GroupAttributes, len(groupAttrsCfg))
	for group, attrs := range groupAttrsCfg {
		attrGroup, err := parseExtraAttrGroup(group)
		if err != nil {
			log.Warn("failed to parse extra attribute group",
				slog.String("group", group),
				slog.String("err", err.Error()),
			)
			continue
		}
		groupAttrs[attrGroup] = attrs
	}

	return groupAttrs
}

func parseExtraAttrGroup(group string) (attrobi.AttrGroups, error) {
	switch group {
	case "k8s_app_meta":
		return GroupAppKube, nil
	default:
		return UndefinedGroup, fmt.Errorf("group %s is not supported", group)
	}
}

func NewBeylaAttrSelector(
	groups attrobi.AttrGroups,
	cfg *attrobi.SelectorConfig,
) (*attrobi.AttrSelector, error) {
	return attrobi.NewCustomAttrSelector(groups, cfg, getDefinitions)
}

// Any new metric and attribute must be added here to be matched from the user-provided wildcard
// selectors of the attributes.select section
func getDefinitions(
	groups attrobi.AttrGroups,
	extraGroupAttributes attrobi.GroupAttributes,
) map[attrobi.Section]attrobi.AttrReportGroup {
	kubeEnabled := groups.Has(GroupKubernetes)
	promEnabled := groups.Has(GroupPrometheus)
	ifaceDirEnabled := groups.Has(GroupNetIfaceDirection)
	cidrEnabled := groups.Has(GroupNetCIDR)

	// attributes to be reported exclusively for prometheus exporters
	prometheusAttributes := newAttrReportGroup(
		!promEnabled,
		nil,
		map[attr.Name]attrobi.Default{
			attr.Instance:         true,
			attr.Job:              true,
			attr.ServiceNamespace: true,
		},
		extraGroupAttributes[GroupPrometheus],
	)

	// ServiceName and ServiceNamespace are reported both as resource and metric attributes, as
	// the OTEL definition requires that it is reported as resource attribute,
	// but Grafana Cloud takes it from the metric
	appAttributes := newAttrReportGroup(
		false,
		[]*attrobi.AttrReportGroup{&prometheusAttributes},
		map[attr.Name]attrobi.Default{
			attr.ServiceName:      true,
			attr.ServiceNamespace: true,
		},
		extraGroupAttributes[GroupApp],
	)

	// network metrics attributes
	networkAttributes := newAttrReportGroup(
		false,
		nil,
		map[attr.Name]attrobi.Default{
			attr.Direction:      true,
			attr.BeylaIP:        false,
			attr.Transport:      false,
			attr.SrcAddress:     false,
			attr.DstAddres:      false,
			attr.SrcPort:        false,
			attr.DstPort:        false,
			attr.SrcName:        false,
			attr.DstName:        false,
			attr.ServerPort:     false,
			attr.ClientPort:     false,
			attr.SrcZone:        false,
			attr.DstZone:        false,
			attr.IfaceDirection: attrobi.Default(ifaceDirEnabled),
			attr.Iface:          attrobi.Default(ifaceDirEnabled),
		},
		extraGroupAttributes[GroupNet],
	)

	// attributes to be reported exclusively for network metrics when
	// kubernetes metadata is enabled
	networkKubeAttributes := newAttrReportGroup(
		!kubeEnabled,
		nil,
		map[attr.Name]attrobi.Default{
			attr.K8sSrcOwnerName: true,
			attr.K8sSrcOwnerType: true,
			attr.K8sSrcNamespace: true,
			attr.K8sDstOwnerName: true,
			attr.K8sDstOwnerType: true,
			attr.K8sDstNamespace: true,
			attr.K8sClusterName:  true,
			attr.K8sSrcName:      false,
			attr.K8sSrcType:      false,
			attr.K8sSrcNodeIP:    false,
			attr.K8sSrcNodeName:  false,
			attr.K8sDstName:      false,
			attr.K8sDstType:      false,
			attr.K8sDstNodeIP:    false,
			attr.K8sDstNodeName:  false,
		},
		extraGroupAttributes[GroupNetKube],
	)

	// network CIDR attributes are only enabled if the CIDRs configuration
	// is defined
	networkCIDR := newAttrReportGroup(
		!cidrEnabled,
		nil,
		map[attr.Name]attrobi.Default{
			attr.DstCIDR: true,
			attr.SrcCIDR: true,
		},
		extraGroupAttributes[attrobi.GroupNetCIDR],
	)

	// networkInterZone* supports the same attributes as
	// network* counterpart, but all of them disabled by default, to keep cardinality low
	networkInterZone := copyDisabled(networkAttributes)
	networkInterZone.Attributes[attr.K8sClusterName] = true
	networkInterZoneKube := copyDisabled(networkKubeAttributes)
	networkInterZoneCIDR := copyDisabled(networkCIDR)
	// only src and dst zone are enabled by default
	networkInterZone.Attributes[attr.SrcZone] = true
	networkInterZone.Attributes[attr.DstZone] = true

	// attributes to be reported exclusively for application metrics when
	// kubernetes metadata is enabled
	appKubeAttributes := newAttrReportGroup(
		!kubeEnabled,
		nil,
		map[attr.Name]attrobi.Default{
			attr.K8sNamespaceName:   true,
			attr.K8sPodName:         true,
			attr.K8sContainerName:   true,
			attr.K8sDeploymentName:  true,
			attr.K8sReplicaSetName:  true,
			attr.K8sDaemonSetName:   true,
			attr.K8sStatefulSetName: true,
			attr.K8sNodeName:        true,
			attr.K8sPodUID:          true,
			attr.K8sPodStartTime:    true,
			attr.K8sClusterName:     true,
			attr.K8sOwnerName:       true,
			attr.K8sKind:            true,
		},
		extraGroupAttributes[GroupAppKube],
	)

	httpRoutes := newAttrReportGroup(
		!groups.Has(GroupHTTPRoutes),
		nil,
		map[attr.Name]attrobi.Default{
			attr.HTTPRoute: true,
		},
		extraGroupAttributes[GroupHTTPRoutes],
	)

	serverInfo := newAttrReportGroup(
		false,
		nil,
		map[attr.Name]attrobi.Default{
			attr.ClientAddr: false,
			attr.ServerAddr: true,
			attr.ServerPort: true,
		},
		extraGroupAttributes[GroupServerInfo],
	)

	httpClientInfo := newAttrReportGroup(
		false,
		nil,
		map[attr.Name]attrobi.Default{
			attr.ServerAddr: true,
			attr.ServerPort: true,
		},
		extraGroupAttributes[GroupHTTPClientInfo],
	)

	grpcClientInfo := newAttrReportGroup(
		false,
		nil,
		map[attr.Name]attrobi.Default{
			attr.ServerAddr: true,
		},
		extraGroupAttributes[GroupGRPCClientInfo],
	)

	httpCommon := newAttrReportGroup(
		false,
		[]*attrobi.AttrReportGroup{&httpRoutes},
		map[attr.Name]attrobi.Default{
			attr.HTTPRequestMethod:      true,
			attr.HTTPResponseStatusCode: true,
			attr.HTTPUrlPath:            false,
		},
		extraGroupAttributes[GroupHTTPCommon],
	)

	// TODO: populate it with host resource attributes in https://opentelemetry.io/docs/specs/semconv/resource/host/
	hostAttributes := newAttrReportGroup(
		false,
		nil,
		map[attr.Name]attrobi.Default{
			attr.HostName: true,
		},
		extraGroupAttributes[GroupHost],
	)

	// the following attributes are only reported as metric attributes in Prometheus,
	// as the OTEL standard defines them as resource attributes.
	promProcessAttributes := newAttrReportGroup(
		!promEnabled,
		nil,
		map[attr.Name]attrobi.Default{
			attr.Instance:             true,
			attr.Job:                  true,
			attrextra.ProcCommand:     true,
			attrextra.ProcOwner:       true,
			attrextra.ProcParentPid:   true,
			attrextra.ProcPid:         true,
			attrextra.ProcCommandLine: false,
			attrextra.ProcCommandArgs: false,
			attrextra.ProcExecName:    false,
			attrextra.ProcExecPath:    false,
		},
		extraGroupAttributes[GroupPromProcess],
	)

	processAttributes := newAttrReportGroup(
		false,
		[]*attrobi.AttrReportGroup{&appKubeAttributes, &hostAttributes, &promProcessAttributes},
		map[attr.Name]attrobi.Default{
			attrextra.ProcCPUMode:   true,
			attrextra.ProcDiskIODir: true,
			attrextra.ProcNetIODir:  true,
		},
		extraGroupAttributes[GroupProcess],
	)

	messagingAttributes := newAttrReportGroup(
		false,
		[]*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes},
		map[attr.Name]attrobi.Default{
			attr.MessagingSystem:      true,
			attr.MessagingDestination: true,
		},
		extraGroupAttributes[GroupMessaging],
	)

	return map[attrobi.Section]attrobi.AttrReportGroup{
		attrobi.BeylaNetworkFlow.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&networkAttributes, &networkCIDR, &networkKubeAttributes},
		},
		attrobi.BeylaNetworkInterZone.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&networkInterZone, &networkInterZoneCIDR, &networkInterZoneKube},
		},
		attrobi.HTTPServerDuration.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &serverInfo},
		},
		attrobi.HTTPServerRequestSize.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &serverInfo},
		},
		attrobi.HTTPServerResponseSize.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &serverInfo},
		},
		attrobi.HTTPClientDuration.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &httpClientInfo},
		},
		attrobi.HTTPClientRequestSize.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &httpClientInfo},
		},
		attrobi.HTTPClientResponseSize.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes, &httpCommon, &httpClientInfo},
		},
		attrobi.RPCClientDuration.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes, &grpcClientInfo},
			Attributes: map[attr.Name]attrobi.Default{
				attr.RPCMethod:         true,
				attr.RPCSystem:         true,
				attr.RPCGRPCStatusCode: true,
			},
		},
		attrobi.RPCServerDuration.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes, &serverInfo},
			Attributes: map[attr.Name]attrobi.Default{
				attr.RPCMethod:         true,
				attr.RPCSystem:         true,
				attr.RPCGRPCStatusCode: true,
			},
		},
		attrobi.DBClientDuration.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]attrobi.Default{
				attr.DBOperation:  true,
				attr.DBSystemName: true,
				attr.ErrorType:    true,
			},
		},
		attrobi.MessagingPublishDuration.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&messagingAttributes},
		},
		attrobi.MessagingProcessDuration.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&messagingAttributes},
		},
		attrobi.Traces.Section: {
			Attributes: map[attr.Name]attrobi.Default{
				attr.DBQueryText: false,
			},
		},
		ProcessCPUUtilization.Section: {SubGroups: []*attrobi.AttrReportGroup{&processAttributes}},
		ProcessCPUTime.Section:        {SubGroups: []*attrobi.AttrReportGroup{&processAttributes}},
		ProcessMemoryUsage.Section:    {SubGroups: []*attrobi.AttrReportGroup{&processAttributes}},
		ProcessMemoryVirtual.Section:  {SubGroups: []*attrobi.AttrReportGroup{&processAttributes}},
		ProcessDiskIO.Section:         {SubGroups: []*attrobi.AttrReportGroup{&processAttributes}},
		ProcessNetIO.Section:          {SubGroups: []*attrobi.AttrReportGroup{&processAttributes}},
		attrobi.GPUKernelLaunchCalls.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]attrobi.Default{
				attr.CudaKernelName: true,
			},
		},
		attrobi.GPUKernelGridSize.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]attrobi.Default{
				attr.CudaKernelName: true,
			},
		},
		attrobi.GPUKernelBlockSize.Section: {
			SubGroups: []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]attrobi.Default{
				attr.CudaKernelName: true,
			},
		},
		attrobi.GPUMemoryAllocations.Section: {
			SubGroups:  []*attrobi.AttrReportGroup{&appAttributes, &appKubeAttributes},
			Attributes: map[attr.Name]attrobi.Default{},
		},
		// span and service graph metrics don't yet implement attribute selection,
		// but their values can still be filtered, so we list them here just to
		// make the filter recognize its attributes
		// TODO: when service graph and spam metrics implement attribute selection, replace this section by proper metric names
		"---- temporary placeholder for span and service graph metrics ----": {
			Attributes: map[attr.Name]attrobi.Default{
				attr.Client:            false,
				attr.ClientNamespace:   false,
				attr.Server:            false,
				attr.ServerNamespace:   false,
				attr.Source:            false,
				attr.ServiceName:       false,
				attr.ServiceInstanceID: false,
				attr.ServiceNamespace:  false,
				attr.SpanKind:          false,
				attr.SpanName:          false,
				attr.StatusCode:        false,
			},
		},
	}
}

func copyDisabled(src attrobi.AttrReportGroup) attrobi.AttrReportGroup {
	var dst = attrobi.AttrReportGroup{
		Disabled:   src.Disabled,
		Attributes: map[attr.Name]attrobi.Default{},
	}
	for k := range src.Attributes {
		dst.Attributes[k] = false
	}
	return dst
}

// AllAttributeNames returns a set with all the names in the attributes database
// as returned by the getDefinitions function
func AllAttributeNames(extraGroupAttributesCfg map[string][]attr.Name) map[attr.Name]struct{} {
	extraGroupAttributes := newGroupAttributes(extraGroupAttributesCfg)
	names := map[attr.Name]struct{}{}
	// -1 to enable all the metric group flags
	for _, section := range getDefinitions(-1, extraGroupAttributes) {
		maps.Copy(names, section.All())
	}
	return names
}
