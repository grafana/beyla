package ebpfcommon

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/request"
)

var spanSet = []request.Span{
	{Pid: request.PidInfo{UserPID: 33, HostPID: 123, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 66, HostPID: 456, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
}

func TestFilter_SameNS(t *testing.T) {
	readNamespace = func(_ uint32) (uint32, error) {
		return 33, nil
	}
	readNamespacePIDs = func(pid uint32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := NewPIDsFilter(slog.With("env", "testing"))
	pf.AllowPID(123)
	pf.AllowPID(456)
	pf.AllowPID(789)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, pf.Filter(spanSet))
}

func TestFilter_DifferentNS(t *testing.T) {
	readNamespace = func(_ uint32) (uint32, error) {
		return 22, nil
	}
	readNamespacePIDs = func(pid uint32) ([]uint32, error) {
		return []uint32{pid}, nil
	}
	pf := NewPIDsFilter(slog.With("env", "testing"))
	pf.AllowPID(123)
	pf.AllowPID(456)
	pf.AllowPID(666)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.Equal(t, []request.Span{}, pf.Filter(spanSet))
}

func TestFilter_Block(t *testing.T) {
	readNamespace = func(_ uint32) (uint32, error) {
		return 33, nil
	}
	readNamespacePIDs = func(pid uint32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := NewPIDsFilter(slog.With("env", "testing"))
	pf.AllowPID(123)
	pf.AllowPID(456)
	pf.BlockPID(123)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, []request.Span{
			{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		}, pf.Filter(spanSet))
	}, 10*time.Second, 10*time.Millisecond, "still haven't seen pid 123 as blocked")
}

func TestFilter_NewNSLater(t *testing.T) {
	readNamespace = func(pid uint32) (uint32, error) {
		if pid == 1000 {
			return 44, nil
		}
		return 33, nil
	}
	readNamespacePIDs = func(pid uint32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := NewPIDsFilter(slog.With("env", "testing"))
	pf.AllowPID(123)
	pf.AllowPID(456)
	pf.AllowPID(789)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, pf.Filter(spanSet))

	pf.AllowPID(1000)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
	}, pf.Filter(spanSet))

	pf.BlockPID(456)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
	}, pf.Filter(spanSet))

	pf.BlockPID(1000)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, pf.Filter(spanSet))
}

func TestNSPidsMap(t *testing.T) {
	readNamespace = func(pid uint32) (uint32, error) {
		return pid + 1000, nil
	}
	readNamespacePIDs = func(pid uint32) ([]uint32, error) {
		return []uint32{pid, pid + 1, pid + 2}, nil
	}
	pm := NewNSPIDsMap[string]()
	require.NoError(t, pm.AddPID(123, "foo"))

	val, ok := pm.Get(1123, 123)
	require.True(t, ok)
	assert.Equal(t, "foo", val)
	val, ok = pm.Get(1123, 124)
	require.True(t, ok)
	assert.Equal(t, "foo", val)
	val, ok = pm.Get(1123, 125)
	require.True(t, ok)
	assert.Equal(t, "foo", val)

	ns, err := pm.RemovePID(123)
	require.NoError(t, err)
	assert.EqualValues(t, 1123, ns)

	_, ok = pm.Get(1123, 123)
	require.False(t, ok)
}
