package surveywatcher

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatcherSpec(t *testing.T) {
	w := &watcher{}
	bundles, err := w.LoadSpecs()
	require.NoError(t, err)
	require.Len(t, bundles, 1)
	spec := bundles[0].Spec
	assert.Equal(t, ebpf.Hash, spec.Maps["survey_socket_pids"].Type, "live evidence must not be LRU-evicted")
	assert.Equal(t, uint32(16), spec.Maps["survey_socket_pids"].KeySize)
	assert.Equal(t, ebpf.RingBuf, spec.Maps["survey_socket_events"].Type)
	assert.Equal(t, ebpf.AttachTraceIter, spec.Programs["survey_seed_sockets"].AttachType)
	assert.Contains(t, w.KProbes(), "security_socket_connect")
	assert.Contains(t, w.KProbes(), "security_socket_listen")
	assert.Contains(t, w.Tracepoints(), "sched/sched_process_exit")
}
