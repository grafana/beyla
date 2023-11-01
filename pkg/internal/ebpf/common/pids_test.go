package ebpfcommon

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/request"
)

var spanSet = []request.Span{
	{Pid: request.PidInfo{UserPID: 33, HostPID: 123, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 66, HostPID: 456, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
	{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
}

func TestFilter_SameNS(t *testing.T) {
	readNamespace = func(_ int32) (uint32, error) {
		return 33, nil
	}
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
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
	readNamespace = func(_ int32) (uint32, error) {
		return 22, nil
	}
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
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
	readNamespace = func(_ int32) (uint32, error) {
		return 33, nil
	}
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
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
