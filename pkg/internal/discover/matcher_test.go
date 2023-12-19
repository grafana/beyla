package discover

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/grafana/beyla/pkg/internal/discover/services"
	"github.com/grafana/beyla/pkg/internal/pipe"
	"github.com/grafana/beyla/pkg/internal/testutil"
)

func TestCriteriaMatcher(t *testing.T) {
	pipeConfig := pipe.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: port-only
    namespace: foo
    open_ports: 80,8080-8089
  - name: exec-only
    exe_path: weird\d
  - name: both
    open_ports: 443
    exe_path_regexp: "server"
`), &pipeConfig))

	matcherFunc, err := CriteriaMatcherProvider(CriteriaMatcher{Cfg: &pipeConfig})
	require.NoError(t, err)
	discoveredProcesses := make(chan []Event[processAttrs], 10)
	filteredProcesses := make(chan []Event[ProcessMatch], 10)
	go matcherFunc(discoveredProcesses, filteredProcesses)
	defer close(discoveredProcesses)

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp processAttrs) (*services.ProcessInfo, error) {
		exePath := map[PID]string{
			1: "/bin/weird33", 2: "/bin/weird33", 3: "server",
			4: "/bin/something", 5: "server", 6: "/bin/clientweird99"}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: exePath, OpenPorts: pp.openPorts}, nil
	}
	discoveredProcesses <- []Event[processAttrs]{
		{Type: EventCreated, Obj: processAttrs{pid: 1, openPorts: []uint32{1, 2, 3}}}, // pass
		{Type: EventDeleted, Obj: processAttrs{pid: 2, openPorts: []uint32{4}}},       // filter
		{Type: EventCreated, Obj: processAttrs{pid: 3, openPorts: []uint32{8433}}},    // filter
		{Type: EventCreated, Obj: processAttrs{pid: 4, openPorts: []uint32{8083}}},    // pass
		{Type: EventCreated, Obj: processAttrs{pid: 5, openPorts: []uint32{443}}},     // pass
		{Type: EventCreated, Obj: processAttrs{pid: 6}},                               // pass
	}

	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 4)
	m := matches[0]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "exec-only", m.Obj.Criteria.Name)
	assert.Equal(t, "", m.Obj.Criteria.Namespace)
	assert.Equal(t, services.ProcessInfo{Pid: 1, ExePath: "/bin/weird33", OpenPorts: []uint32{1, 2, 3}}, *m.Obj.Process)
	m = matches[1]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "port-only", m.Obj.Criteria.Name)
	assert.Equal(t, "foo", m.Obj.Criteria.Namespace)
	assert.Equal(t, services.ProcessInfo{Pid: 4, ExePath: "/bin/something", OpenPorts: []uint32{8083}}, *m.Obj.Process)
	m = matches[2]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "both", m.Obj.Criteria.Name)
	assert.Equal(t, "", m.Obj.Criteria.Namespace)
	assert.Equal(t, services.ProcessInfo{Pid: 5, ExePath: "server", OpenPorts: []uint32{443}}, *m.Obj.Process)
	m = matches[3]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "exec-only", m.Obj.Criteria.Name)
	assert.Equal(t, "", m.Obj.Criteria.Namespace)
	assert.Equal(t, services.ProcessInfo{Pid: 6, ExePath: "/bin/clientweird99"}, *m.Obj.Process)
}

func TestCriteriaMatcher_MustMatchAllAttributes(t *testing.T) {
	pipeConfig := pipe.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: all-attributes-must-match
    namespace: foons
    open_ports: 80,8080-8089
    exe_path: foo
    k8s_namespace: thens
    k8s_pod_name: thepod
    k8s_deployment_name: thedepl
    k8s_replicaset_name: thers
`), &pipeConfig))

	matcherFunc, err := CriteriaMatcherProvider(CriteriaMatcher{Cfg: &pipeConfig})
	require.NoError(t, err)
	discoveredProcesses := make(chan []Event[processAttrs], 10)
	filteredProcesses := make(chan []Event[ProcessMatch], 10)
	go matcherFunc(discoveredProcesses, filteredProcesses)
	defer close(discoveredProcesses)

	processInfo = func(pp processAttrs) (*services.ProcessInfo, error) {
		exePath := map[PID]string{
			1: "/bin/foo", 2: "/bin/faa", 3: "foo",
			4: "foool", 5: "thefoool", 6: "foo"}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: exePath, OpenPorts: pp.openPorts}, nil
	}
	allMeta := map[string]string{
		"k8s_namespace":       "thens",
		"k8s_pod_name":        "is-thepod",
		"k8s_deployment_name": "thedeployment",
		"k8s_replicaset_name": "thers",
	}
	incompleteMeta := map[string]string{
		"k8s_namespace":       "thens",
		"k8s_pod_name":        "is-thepod",
		"k8s_replicaset_name": "thers",
	}
	differentMeta := map[string]string{
		"k8s_namespace":       "thens",
		"k8s_pod_name":        "is-thepod",
		"k8s_deployment_name": "some-deployment",
		"k8s_replicaset_name": "thers",
	}
	discoveredProcesses <- []Event[processAttrs]{
		{Type: EventCreated, Obj: processAttrs{pid: 1, openPorts: []uint32{8081}, metadata: allMeta}},        // pass
		{Type: EventDeleted, Obj: processAttrs{pid: 2, openPorts: []uint32{4}, metadata: allMeta}},           // filter: executable does not match
		{Type: EventCreated, Obj: processAttrs{pid: 3, openPorts: []uint32{7777}, metadata: allMeta}},        // filter: port does not match
		{Type: EventCreated, Obj: processAttrs{pid: 4, openPorts: []uint32{8083}, metadata: incompleteMeta}}, // filter: not all metadata available
		{Type: EventCreated, Obj: processAttrs{pid: 5, openPorts: []uint32{80}}},                             // filter: no metadata
		{Type: EventCreated, Obj: processAttrs{pid: 6, openPorts: []uint32{8083}, metadata: differentMeta}},  // filter: not all metadata matches
	}
	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 1)
	m := matches[0]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "all-attributes-must-match", m.Obj.Criteria.Name)
	assert.Equal(t, "foons", m.Obj.Criteria.Namespace)
	assert.Equal(t, services.ProcessInfo{Pid: 1, ExePath: "/bin/foo", OpenPorts: []uint32{8081}}, *m.Obj.Process)
}
