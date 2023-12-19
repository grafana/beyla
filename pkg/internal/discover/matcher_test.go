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
		{Type: EventCreated, Obj: processAttrs{pid: 4, openPorts: []uint32{8083}}},    //pass
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

// TODO matcher tests for attributes
