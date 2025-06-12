package discover

import (
	"regexp"
	"testing"

	"github.com/gobwas/glob"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/pipe/msg"
	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/services"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/grafana/beyla/v2/pkg/beyla"
	"github.com/grafana/beyla/v2/pkg/internal/testutil"
	servicesextra "github.com/grafana/beyla/v2/pkg/services"
)

func TestCriteriaMatcher(t *testing.T) {
	pipeConfig := beyla.Config{}
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

	discoveredProcesses := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := CriteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp processAttrs) (*services.ProcessInfo, error) {
		exePath := map[PID]string{
			1: "/bin/weird33", 2: "/bin/weird33", 3: "server",
			4: "/bin/something", 5: "server", 6: "/bin/clientweird99"}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: exePath, OpenPorts: pp.openPorts}, nil
	}
	discoveredProcesses.Send([]Event[processAttrs]{
		{Type: EventCreated, Obj: processAttrs{pid: 1, openPorts: []uint32{1, 2, 3}}}, // pass
		{Type: EventDeleted, Obj: processAttrs{pid: 2, openPorts: []uint32{4}}},       // filter
		{Type: EventCreated, Obj: processAttrs{pid: 3, openPorts: []uint32{8433}}},    // filter
		{Type: EventCreated, Obj: processAttrs{pid: 4, openPorts: []uint32{8083}}},    // pass
		{Type: EventCreated, Obj: processAttrs{pid: 5, openPorts: []uint32{443}}},     // pass
		{Type: EventCreated, Obj: processAttrs{pid: 6}},                               // pass
	})

	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 4)
	m := matches[0]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "exec-only", m.Obj.Criteria.GetName())
	assert.Equal(t, "", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 1, ExePath: "/bin/weird33", OpenPorts: []uint32{1, 2, 3}}, *m.Obj.Process)
	m = matches[1]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "port-only", m.Obj.Criteria.GetName())
	assert.Equal(t, "foo", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 4, ExePath: "/bin/something", OpenPorts: []uint32{8083}}, *m.Obj.Process)
	m = matches[2]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "both", m.Obj.Criteria.GetName())
	assert.Equal(t, "", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 5, ExePath: "server", OpenPorts: []uint32{443}}, *m.Obj.Process)
	m = matches[3]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "exec-only", m.Obj.Criteria.GetName())
	assert.Equal(t, "", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 6, ExePath: "/bin/clientweird99"}, *m.Obj.Process)
}

func TestCriteriaMatcher_Exclude(t *testing.T) {
	pipeConfig := beyla.Config{}
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
  exclude_services:
  - exe_path: s
`), &pipeConfig))

	discoveredProcesses := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := CriteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp processAttrs) (*services.ProcessInfo, error) {
		exePath := map[PID]string{
			1: "/bin/weird33", 2: "/bin/weird33", 3: "server",
			4: "/bin/something", 5: "server", 6: "/bin/clientweird99"}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: exePath, OpenPorts: pp.openPorts}, nil
	}
	discoveredProcesses.Send([]Event[processAttrs]{
		{Type: EventCreated, Obj: processAttrs{pid: 1, openPorts: []uint32{1, 2, 3}}}, // pass
		{Type: EventDeleted, Obj: processAttrs{pid: 2, openPorts: []uint32{4}}},       // filter
		{Type: EventCreated, Obj: processAttrs{pid: 3, openPorts: []uint32{8433}}},    // filter
		{Type: EventCreated, Obj: processAttrs{pid: 4, openPorts: []uint32{8083}}},    // filter (in exclude)
		{Type: EventCreated, Obj: processAttrs{pid: 5, openPorts: []uint32{443}}},     // filter (in exclude)
		{Type: EventCreated, Obj: processAttrs{pid: 6}},                               // pass
	})

	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 2)
	m := matches[0]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "exec-only", m.Obj.Criteria.GetName())
	assert.Equal(t, "", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 1, ExePath: "/bin/weird33", OpenPorts: []uint32{1, 2, 3}}, *m.Obj.Process)
	m = matches[1]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "exec-only", m.Obj.Criteria.GetName())
	assert.Equal(t, "", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 6, ExePath: "/bin/clientweird99"}, *m.Obj.Process)
}

func TestCriteriaMatcher_Exclude_Metadata(t *testing.T) {
	pipeConfig := beyla.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - k8s_node_name: .
  exclude_services:
  - k8s_node_name: bar
`), &pipeConfig))

	discoveredProcesses := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := CriteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp processAttrs) (*services.ProcessInfo, error) {
		exePath := map[PID]string{
			1: "/bin/weird33", 2: "/bin/weird33", 3: "server",
			4: "/bin/something", 5: "server", 6: "/bin/clientweird99"}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: exePath, OpenPorts: pp.openPorts}, nil
	}
	nodeFoo := map[string]string{"k8s_node_name": "foo"}
	nodeBar := map[string]string{"k8s_node_name": "bar"}
	discoveredProcesses.Send([]Event[processAttrs]{
		{Type: EventCreated, Obj: processAttrs{pid: 1, metadata: nodeFoo}}, // pass
		{Type: EventDeleted, Obj: processAttrs{pid: 2, metadata: nodeFoo}}, // filter
		{Type: EventCreated, Obj: processAttrs{pid: 3, metadata: nodeFoo}}, // pass
		{Type: EventCreated, Obj: processAttrs{pid: 4, metadata: nodeBar}}, // filter (in exclude)
		{Type: EventDeleted, Obj: processAttrs{pid: 5, metadata: nodeFoo}}, // filter
		{Type: EventCreated, Obj: processAttrs{pid: 6, metadata: nodeBar}}, // filter (in exclude)
	})

	matches := testutil.ReadChannel(t, filteredProcesses, 1000*testTimeout)
	require.Len(t, matches, 2)
	m := matches[0]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, services.ProcessInfo{Pid: 1, ExePath: "/bin/weird33"}, *m.Obj.Process)
	m = matches[1]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, services.ProcessInfo{Pid: 3, ExePath: "server"}, *m.Obj.Process)
}

func TestCriteriaMatcher_MustMatchAllAttributes(t *testing.T) {
	pipeConfig := beyla.Config{}
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

	discoveredProcesses := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := CriteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

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
	discoveredProcesses.Send([]Event[processAttrs]{
		{Type: EventCreated, Obj: processAttrs{pid: 1, openPorts: []uint32{8081}, metadata: allMeta}},        // pass
		{Type: EventDeleted, Obj: processAttrs{pid: 2, openPorts: []uint32{4}, metadata: allMeta}},           // filter: executable does not match
		{Type: EventCreated, Obj: processAttrs{pid: 3, openPorts: []uint32{7777}, metadata: allMeta}},        // filter: port does not match
		{Type: EventCreated, Obj: processAttrs{pid: 4, openPorts: []uint32{8083}, metadata: incompleteMeta}}, // filter: not all metadata available
		{Type: EventCreated, Obj: processAttrs{pid: 5, openPorts: []uint32{80}}},                             // filter: no metadata
		{Type: EventCreated, Obj: processAttrs{pid: 6, openPorts: []uint32{8083}, metadata: differentMeta}},  // filter: not all metadata matches
	})
	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 1)
	m := matches[0]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "all-attributes-must-match", m.Obj.Criteria.GetName())
	assert.Equal(t, "foons", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 1, ExePath: "/bin/foo", OpenPorts: []uint32{8081}}, *m.Obj.Process)
}

func TestCriteriaMatcherMissingPort(t *testing.T) {
	pipeConfig := beyla.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: port-only
    namespace: foo
    open_ports: 80
`), &pipeConfig))

	discoveredProcesses := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := CriteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp processAttrs) (*services.ProcessInfo, error) {
		proc := map[PID]struct {
			Exe  string
			PPid int32
		}{
			1: {Exe: "/bin/weird33", PPid: 0}, 2: {Exe: "/bin/weird33", PPid: 16}, 3: {Exe: "/bin/weird33", PPid: 1}}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: proc.Exe, PPid: proc.PPid, OpenPorts: pp.openPorts}, nil
	}
	discoveredProcesses.Send([]Event[processAttrs]{
		{Type: EventCreated, Obj: processAttrs{pid: 1, openPorts: []uint32{80}}}, // this one is the parent, matches on port
		{Type: EventDeleted, Obj: processAttrs{pid: 2, openPorts: []uint32{}}},   // we'll skip 2 since PPid is 16, not 1
		{Type: EventCreated, Obj: processAttrs{pid: 3, openPorts: []uint32{}}},   // this one is the child, without port, but matches the parent by port
	})

	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 2)
	m := matches[0]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "port-only", m.Obj.Criteria.GetName())
	assert.Equal(t, "foo", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 1, ExePath: "/bin/weird33", OpenPorts: []uint32{80}, PPid: 0}, *m.Obj.Process)
	m = matches[1]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "port-only", m.Obj.Criteria.GetName())
	assert.Equal(t, "foo", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 3, ExePath: "/bin/weird33", OpenPorts: []uint32{}, PPid: 1}, *m.Obj.Process)
}

func TestCriteriaMatcherContainersOnly(t *testing.T) {
	pipeConfig := beyla.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - name: port-only-containers
    namespace: foo
    open_ports: 80
    containers_only: true
`), &pipeConfig))

	// override the namespace fetcher
	namespaceFetcherFunc = func(pid int32) (string, error) {
		switch pid {
		case 1:
			return "1", nil
		case 2:
			return "2", nil
		case 3:
			return "3", nil
		}
		panic("pid not exposed by test")
	}

	// override the os.Getpid func to that Beyla is always reported
	// with pid 1
	osPidFunc = func() int {
		return 1
	}

	discoveredProcesses := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := CriteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	// it will filter unmatching processes and return a ProcessMatch for these that match
	processInfo = func(pp processAttrs) (*services.ProcessInfo, error) {
		proc := map[PID]struct {
			Exe  string
			PPid int32
		}{
			1: {Exe: "/bin/weird33", PPid: 0}, 2: {Exe: "/bin/weird33", PPid: 0}, 3: {Exe: "/bin/weird33", PPid: 1}}[pp.pid]
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: proc.Exe, PPid: proc.PPid, OpenPorts: pp.openPorts}, nil
	}
	discoveredProcesses.Send([]Event[processAttrs]{
		{Type: EventCreated, Obj: processAttrs{pid: 1, openPorts: []uint32{80}}}, // this one is the parent, matches on port, not in container
		{Type: EventCreated, Obj: processAttrs{pid: 2, openPorts: []uint32{80}}}, // another pid, but in a container
		{Type: EventCreated, Obj: processAttrs{pid: 3, openPorts: []uint32{80}}}, // this one is the child, without port, but matches the parent by port, in a container
	})

	matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
	require.Len(t, matches, 2)
	m := matches[0]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "port-only-containers", m.Obj.Criteria.GetName())
	assert.Equal(t, "foo", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 2, ExePath: "/bin/weird33", OpenPorts: []uint32{80}, PPid: 0}, *m.Obj.Process)
	m = matches[1]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, "port-only-containers", m.Obj.Criteria.GetName())
	assert.Equal(t, "foo", m.Obj.Criteria.GetNamespace())
	assert.Equal(t, services.ProcessInfo{Pid: 3, ExePath: "/bin/weird33", OpenPorts: []uint32{80}, PPid: 1}, *m.Obj.Process)
}

func TestInstrumentation_CoexistingWithDeprecatedServices(t *testing.T) {
	// setup conflicting criteria and see how some of them are ignored and others not
	type testCase struct {
		name string
		cfg  beyla.Config
	}
	pass := services.NewGlob(glob.MustCompile("*/must-pass"))
	notPass := services.NewGlob(glob.MustCompile("*/dont-pass"))
	neitherPass := services.NewGlob(glob.MustCompile("*/neither-pass"))
	bothPass := services.NewGlob(glob.MustCompile("*/{must,also}-pass"))

	passPort := services.PortEnum{Ranges: []services.PortRange{{Start: 80}}}
	allPorts := services.PortEnum{Ranges: []services.PortRange{{Start: 1, End: 65535}}}

	passRE := services.NewPathRegexp(regexp.MustCompile("must-pass"))
	notPassRE := services.NewPathRegexp(regexp.MustCompile("dont-pass"))
	neitherPassRE := services.NewPathRegexp(regexp.MustCompile("neither-pass"))
	bothPassRE := services.NewPathRegexp(regexp.MustCompile("(must|also)-pass"))

	for _, tc := range []testCase{
		{name: "discovery > instrument", cfg: beyla.Config{Discovery: servicesextra.BeylaDiscoveryConfig{
			Instrument: services.GlobDefinitionCriteria{{Path: pass}, {OpenPorts: passPort}},
		}}},
		{
			name: "discovery > instrument with discovery > exclude_instrument && default_exclude_instrument",
			cfg: beyla.Config{Discovery: servicesextra.BeylaDiscoveryConfig{
				Instrument:               services.GlobDefinitionCriteria{{OpenPorts: allPorts}},
				ExcludeInstrument:        services.GlobDefinitionCriteria{{Path: notPass}},
				DefaultExcludeInstrument: services.GlobDefinitionCriteria{{Path: neitherPass}},
			}},
		},
		{
			name: "discovery > instrument with deprecated discovery > services",
			cfg: beyla.Config{Discovery: servicesextra.BeylaDiscoveryConfig{
				Instrument: services.GlobDefinitionCriteria{{Path: pass}, {OpenPorts: passPort}},
				// To be ignored
				Services: services.RegexDefinitionCriteria{{OpenPorts: allPorts}},
			}},
		},
		{
			name: "discovery > instrument with top-level auto-target-exec option",
			cfg: beyla.Config{Discovery: servicesextra.BeylaDiscoveryConfig{
				Instrument: services.GlobDefinitionCriteria{{OpenPorts: passPort}},
			}, AutoTargetExe: pass},
		},
		{
			name: "discovery > instrument with top-level ports option",
			cfg: beyla.Config{Discovery: servicesextra.BeylaDiscoveryConfig{
				Instrument: services.GlobDefinitionCriteria{{Path: pass}},
			}, Port: passPort},
		},
		{
			name: "discovery > instrument ignoring deprecated path option",
			cfg: beyla.Config{Discovery: servicesextra.BeylaDiscoveryConfig{
				Instrument: services.GlobDefinitionCriteria{{Path: pass}, {OpenPorts: passPort}},
			}, Exec: services.NewPathRegexp(regexp.MustCompile("dont-pass"))},
		},
		// cases below would be removed if the deprecated discovery > services options are removed,
		{name: "deprecated discovery > services", cfg: beyla.Config{Discovery: servicesextra.BeylaDiscoveryConfig{
			Services: services.RegexDefinitionCriteria{{Path: passRE}, {OpenPorts: passPort}},
		}}},
		{
			name: "deprecated discovery > services with discovery > exclude_services && default_exclude_services",
			cfg: beyla.Config{Discovery: servicesextra.BeylaDiscoveryConfig{
				Services:               services.RegexDefinitionCriteria{{OpenPorts: allPorts}},
				ExcludeServices:        services.RegexDefinitionCriteria{{Path: notPassRE}},
				DefaultExcludeServices: services.RegexDefinitionCriteria{{Path: neitherPassRE}},
			}},
		},
		{
			name: "deprecated discovery > services with top-level deprecated exec option",
			cfg: beyla.Config{Discovery: servicesextra.BeylaDiscoveryConfig{
				Services: services.RegexDefinitionCriteria{{OpenPorts: passPort}},
			}, Exec: passRE},
		},
		{
			name: "deprecated discovery > services with top-level deprecated port option",
			cfg: beyla.Config{Discovery: servicesextra.BeylaDiscoveryConfig{
				Services: services.RegexDefinitionCriteria{{Path: passRE}},
			}, Port: passPort},
		},
		{
			name: "no YAML discovery section, using top-level AutoTargetExe variable",
			cfg:  beyla.Config{AutoTargetExe: bothPass},
		},
		{
			name: "no YAML discovery section, using deprecated top-level discovery variables",
			cfg:  beyla.Config{Exec: bothPassRE},
		},
		{name: "prioritizing top-level AutoTarget variable over deprecated exec", cfg: beyla.Config{
			AutoTargetExe: bothPass,
			// to be ignored
			Exec: notPassRE,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// it will filter unmatching processes and return a ProcessMatch for these that match
			processInfo = func(pp processAttrs) (*services.ProcessInfo, error) {
				proc := map[PID]struct {
					Exe  string
					PPid int32
				}{
					1:  {Exe: "/bin/must-pass", PPid: 0},
					2:  {Exe: "/bin/also-pass", PPid: 0},
					11: {Exe: "/bin/dont-pass", PPid: 0},
					12: {Exe: "/bin/neither-pass", PPid: 0},
				}[pp.pid]
				return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: proc.Exe, PPid: proc.PPid, OpenPorts: pp.openPorts}, nil
			}
			discoveredProcesses := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
			filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
			filteredProcesses := filteredProcessesQu.Subscribe()
			matcherFunc, err := CriteriaMatcherProvider(&tc.cfg, discoveredProcesses, filteredProcessesQu)(t.Context())
			require.NoError(t, err)
			go matcherFunc(t.Context())
			defer filteredProcessesQu.Close()

			discoveredProcesses.Send([]Event[processAttrs]{
				{Type: EventCreated, Obj: processAttrs{pid: 1, openPorts: []uint32{1234}}},
				{Type: EventCreated, Obj: processAttrs{pid: 2, openPorts: []uint32{80}}},
				{Type: EventCreated, Obj: processAttrs{pid: 11, openPorts: []uint32{4321}}},
				{Type: EventCreated, Obj: processAttrs{pid: 12, openPorts: []uint32{3456}}},
			})

			matches := testutil.ReadChannel(t, filteredProcesses, testTimeout)
			require.Len(t, matches, 2)
			m := matches[0]
			assert.Equal(t, EventCreated, m.Type)
			assert.Equal(t, services.ProcessInfo{Pid: 1, ExePath: "/bin/must-pass", OpenPorts: []uint32{1234}}, *m.Obj.Process)
			m = matches[1]
			assert.Equal(t, EventCreated, m.Type)
			assert.Equal(t, services.ProcessInfo{Pid: 2, ExePath: "/bin/also-pass", OpenPorts: []uint32{80}}, *m.Obj.Process)
		})
	}
}

func criteriaMatcherExcludeDefaultMetadataHelper(t *testing.T, pipeConfig beyla.Config) {
	k8sSystemNamespaces := []string{
		"gke-connect", "gke-gmp-system", "gke-managed-cim", "gke-managed-filestorecsi",
		"gke-managed-metrics-server", "gke-managed-system", "gke-system", "gke-managed-volumepopulator",
		"gatekeeper-system", "kube-system", "kube-node-lease", "local-path-storage", "grafana-alloy",
		"cert-manager", "monitoring",
	}

	k8sAllowedNamespaces := []string{"default", "random-service-namespace"}

	discoveredProcesses := msg.NewQueue[[]Event[processAttrs]](msg.ChannelBufferLen(10))
	filteredProcessesQu := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	filteredProcesses := filteredProcessesQu.Subscribe()
	matcherFunc, err := CriteriaMatcherProvider(&pipeConfig, discoveredProcesses, filteredProcessesQu)(t.Context())
	require.NoError(t, err)
	go matcherFunc(t.Context())
	defer filteredProcessesQu.Close()

	processInfo = func(pp processAttrs) (*services.ProcessInfo, error) {
		return &services.ProcessInfo{Pid: int32(pp.pid), ExePath: "/something/something", PPid: 1}, nil
	}

	pid := 1
	events := []Event[processAttrs]{}

	for _, ns := range k8sSystemNamespaces {
		events = append(events,
			Event[processAttrs]{Type: EventCreated, Obj: processAttrs{pid: PID(pid), metadata: map[string]string{"k8s_namespace": ns}}},
		)
		pid++
	}

	savePid := pid

	for _, ns := range k8sAllowedNamespaces {
		events = append(events,
			Event[processAttrs]{Type: EventCreated, Obj: processAttrs{pid: PID(pid), metadata: map[string]string{"k8s_namespace": ns}}},
		)
		pid++
	}

	discoveredProcesses.Send(events)

	matches := testutil.ReadChannel(t, filteredProcesses, 1000*testTimeout)
	require.Len(t, matches, 2)
	m := matches[0]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, services.ProcessInfo{Pid: int32(savePid), PPid: 1, ExePath: "/something/something"}, *m.Obj.Process)
	m = matches[1]
	assert.Equal(t, EventCreated, m.Type)
	assert.Equal(t, services.ProcessInfo{Pid: int32(savePid + 1), PPid: 1, ExePath: "/something/something"}, *m.Obj.Process)
}

func TestCriteriaMatcher_Exclude_Default_Metadata_Regex(t *testing.T) {
	pipeConfig := beyla.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  services:
  - k8s_namespace: .
`), &pipeConfig))

	pipeConfig.Discovery.DefaultExcludeServices = beyla.DefaultConfig.Discovery.DefaultExcludeServices

	criteriaMatcherExcludeDefaultMetadataHelper(t, pipeConfig)
}

func TestCriteriaMatcher_Exclude_Default_Metadata_Glob(t *testing.T) {
	pipeConfig := beyla.Config{}
	require.NoError(t, yaml.Unmarshal([]byte(`discovery:
  instrument:
  - k8s_namespace: "*"
`), &pipeConfig))

	pipeConfig.Discovery.DefaultExcludeInstrument = beyla.DefaultConfig.Discovery.DefaultExcludeInstrument

	criteriaMatcherExcludeDefaultMetadataHelper(t, pipeConfig)
}
