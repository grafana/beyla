package ebpfcommon

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
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
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := NewPIDsFilter(slog.With("env", "testing"))
	pf.AllowPID(123, 33, svc.ID{}, PIDTypeGo)
	pf.AllowPID(456, 33, svc.ID{}, PIDTypeGo)
	pf.AllowPID(789, 33, svc.ID{}, PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, pf.Filter(spanSet))
}

func TestFilter_DifferentNS(t *testing.T) {
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := NewPIDsFilter(slog.With("env", "testing"))
	pf.AllowPID(123, 22, svc.ID{}, PIDTypeGo)
	pf.AllowPID(456, 22, svc.ID{}, PIDTypeGo)
	pf.AllowPID(666, 22, svc.ID{}, PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.Equal(t, []request.Span{}, pf.Filter(spanSet))
}

func TestFilter_Block(t *testing.T) {
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := NewPIDsFilter(slog.With("env", "testing"))
	pf.AllowPID(123, 33, svc.ID{}, PIDTypeGo)
	pf.AllowPID(456, 33, svc.ID{}, PIDTypeGo)
	pf.BlockPID(123, 33)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, []request.Span{
			{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		}, pf.Filter(spanSet))
	}, 10*time.Second, 10*time.Millisecond, "still haven't seen pid 123 as blocked")
}

func TestFilter_NewNSLater(t *testing.T) {
	readNamespacePIDs = func(pid int32) ([]uint32, error) {
		return []uint32{uint32(pid)}, nil
	}
	pf := NewPIDsFilter(slog.With("env", "testing"))
	pf.AllowPID(123, 33, svc.ID{}, PIDTypeGo)
	pf.AllowPID(456, 33, svc.ID{}, PIDTypeGo)
	pf.AllowPID(789, 33, svc.ID{}, PIDTypeGo)

	// with the same namespace, it filters by user PID, as it is the PID
	// that is seen by Beyla's process discovery
	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, pf.Filter(spanSet))

	pf.AllowPID(1000, 44, svc.ID{}, PIDTypeGo)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 456, HostPID: 666, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
	}, pf.Filter(spanSet))

	pf.BlockPID(456, 33)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 1000, HostPID: 1234, Namespace: 44}},
	}, pf.Filter(spanSet))

	pf.BlockPID(1000, 44)

	assert.Equal(t, []request.Span{
		{Pid: request.PidInfo{UserPID: 123, HostPID: 333, Namespace: 33}},
		{Pid: request.PidInfo{UserPID: 789, HostPID: 234, Namespace: 33}},
	}, pf.Filter(spanSet))
}
