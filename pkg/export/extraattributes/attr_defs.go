package extraattributes

import (
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"

	names "github.com/grafana/beyla/v2/pkg/export/extraattributes/names"
)

const (
	GroupPromProcess = attributes.AttrGroups(iota + 1000)
	GroupProcess
)

func NewBeylaAttrSelector(
	groups attributes.AttrGroups,
	cfg *attributes.SelectorConfig,
) (*attributes.AttrSelector, error) {
	return attributes.NewCustomAttrSelector(groups, cfg, getDefinitions)
}

// Any new metric and attribute must be added here to be matched from the user-provided wildcard
// selectors of the attributes.select section
func getDefinitions(
	groups attributes.AttrGroups,
	extraGroupAttributes attributes.GroupAttributes,
) map[attributes.Section]attributes.AttrReportGroup {
	kubeEnabled := groups.Has(attributes.GroupKubernetes)
	promEnabled := groups.Has(attributes.GroupPrometheus)

	appKubeAttributes := attributes.NewAttrReportGroup(
		!kubeEnabled,
		nil,
		map[attr.Name]attributes.Default{
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
		extraGroupAttributes[attributes.GroupAppKube],
	)

	// TODO: populate it with host resource attributes in https://opentelemetry.io/docs/specs/semconv/resource/host/
	hostAttributes := attributes.NewAttrReportGroup(
		false,
		nil,
		map[attr.Name]attributes.Default{
			attr.HostName: true,
		},
		extraGroupAttributes[attributes.GroupHost],
	)

	// the following attributes are only reported as metric attributes in Prometheus,
	// as the OTEL standard defines them as resource attributes.
	promProcessAttributes := attributes.NewAttrReportGroup(
		!promEnabled,
		nil,
		map[attr.Name]attributes.Default{
			attr.Instance:         true,
			attr.Job:              true,
			names.ProcCommand:     true,
			names.ProcOwner:       true,
			names.ProcParentPid:   true,
			names.ProcPid:         true,
			names.ProcCommandLine: false,
			names.ProcCommandArgs: false,
			names.ProcExecName:    false,
			names.ProcExecPath:    false,
		},
		extraGroupAttributes[GroupPromProcess],
	)

	processAttributes := attributes.NewAttrReportGroup(
		false,
		[]*attributes.AttrReportGroup{&appKubeAttributes, &hostAttributes, &promProcessAttributes},
		map[attr.Name]attributes.Default{
			names.ProcCPUMode:   true,
			names.ProcDiskIODir: true,
			names.ProcNetIODir:  true,
		},
		extraGroupAttributes[GroupProcess],
	)

	return map[attributes.Section]attributes.AttrReportGroup{
		ProcessCPUUtilization.Section: {SubGroups: []*attributes.AttrReportGroup{&processAttributes}},
		ProcessCPUTime.Section:        {SubGroups: []*attributes.AttrReportGroup{&processAttributes}},
		ProcessMemoryUsage.Section:    {SubGroups: []*attributes.AttrReportGroup{&processAttributes}},
		ProcessMemoryVirtual.Section:  {SubGroups: []*attributes.AttrReportGroup{&processAttributes}},
		ProcessDiskIO.Section:         {SubGroups: []*attributes.AttrReportGroup{&processAttributes}},
		ProcessNetIO.Section:          {SubGroups: []*attributes.AttrReportGroup{&processAttributes}},
	}
}
