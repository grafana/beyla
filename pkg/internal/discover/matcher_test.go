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
    exe_path_regexp: weird\d
  - name: both
    open_ports: 443
    exe_path_regexp: "server"
`), &pipeConfig))

	matcherFunc, err := CriteriaMatcherProvider(CriteriaMatcher{Cfg: &pipeConfig})
	require.NoError(t, err)
	discoveredProcesses := make(chan []Event[*services.ProcessInfo], 10)
	filteredProcesses := make(chan []Event[ProcessMatch], 10)
	go matcherFunc(discoveredProcesses, filteredProcesses)
	defer close(discoveredProcesses)

	// it will filter unmatching processes and return a ProcessMatch for these that match
	discoveredProcesses <- []Event[*services.ProcessInfo]{
		{Type: EventCreated, Obj: &services.ProcessInfo{ExePath: "/bin/weird33", OpenPorts: []uint32{1, 2, 3}}}, // pass
		{Type: EventDeleted, Obj: &services.ProcessInfo{ExePath: "/bin/weird33", OpenPorts: []uint32{4}}},       // filter
		{Type: EventCreated, Obj: &services.ProcessInfo{ExePath: "server", OpenPorts: []uint32{8433}}},          // filter
		{Type: EventCreated, Obj: &services.ProcessInfo{ExePath: "/bin/something", OpenPorts: []uint32{8083}}},  //pass
		{Type: EventCreated, Obj: &services.ProcessInfo{ExePath: "server", OpenPorts: []uint32{443}}},           // pass
		{Type: EventCreated, Obj: &services.ProcessInfo{ExePath: "/bin/clientweird99"}},                         // pass
	}

	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 4)
	m := matches[0]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "exec-only", m.Obj.Criteria.Name)
	assert.Equal(t, "", m.Obj.Criteria.Namespace)
	assert.Equal(t, services.ProcessInfo{ExePath: "/bin/weird33", OpenPorts: []uint32{1, 2, 3}}, *m.Obj.Process)
	m = matches[1]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "port-only", m.Obj.Criteria.Name)
	assert.Equal(t, "foo", m.Obj.Criteria.Namespace)
	assert.Equal(t, services.ProcessInfo{ExePath: "/bin/something", OpenPorts: []uint32{8083}}, *m.Obj.Process)
	m = matches[2]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "both", m.Obj.Criteria.Name)
	assert.Equal(t, "", m.Obj.Criteria.Namespace)
	assert.Equal(t, services.ProcessInfo{ExePath: "server", OpenPorts: []uint32{443}}, *m.Obj.Process)
	m = matches[3]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "exec-only", m.Obj.Criteria.Name)
	assert.Equal(t, "", m.Obj.Criteria.Namespace)
	assert.Equal(t, services.ProcessInfo{ExePath: "/bin/clientweird99"}, *m.Obj.Process)
}
