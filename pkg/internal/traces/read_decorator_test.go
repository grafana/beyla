package traces

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
	"github.com/grafana/beyla/pkg/internal/testutil"
	"github.com/grafana/beyla/pkg/internal/traces/hostname"
)

const testTimeout = 5 * time.Second

func TestReadDecorator(t *testing.T) {
	localHostname, _, err := hostname.CreateResolver("", "", false).Query()
	require.NoError(t, err)
	require.NotEmpty(t, localHostname)
	dnsHostname, _, err := hostname.CreateResolver("", "", true).Query()
	require.NoError(t, err)
	require.NotEmpty(t, dnsHostname)

	type testCase struct {
		desc     string
		cfg      ReadDecorator
		expected string
	}
	for _, tc := range []testCase{{
		desc:     "dns",
		cfg:      ReadDecorator{InstanceID: InstanceIDConfig{HostnameDNSResolution: true}},
		expected: dnsHostname + "-1234",
	}, {
		desc:     "no-dns",
		expected: localHostname + "-1234",
	}, {
		desc:     "override hostname",
		cfg:      ReadDecorator{InstanceID: InstanceIDConfig{OverrideHostname: "foooo"}},
		expected: "foooo-1234",
	}, {
		desc:     "override HN",
		cfg:      ReadDecorator{InstanceID: InstanceIDConfig{OverrideInstanceID: "instanceee"}},
		expected: "instanceee",
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			cfg := tc.cfg
			rawInput := make(chan []request.Span, 10)
			decoratedOutput := make(chan []request.Span, 10)
			cfg.TracesInput = rawInput
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			readLoop, err := ReadFromChannel(ctx, cfg)
			require.NoError(t, err)
			go readLoop(decoratedOutput)
			rawInput <- []request.Span{
				{Path: "/foo", Pid: request.PidInfo{HostPID: 1234}},
				{Path: "/bar", Pid: request.PidInfo{HostPID: 1234}},
			}
			outSpans := testutil.ReadChannel(t, decoratedOutput, testTimeout)
			assert.Equal(t, []request.Span{
				{ServiceID: svc.ID{Instance: tc.expected}, Path: "/foo", Pid: request.PidInfo{HostPID: 1234}},
				{ServiceID: svc.ID{Instance: tc.expected}, Path: "/bar", Pid: request.PidInfo{HostPID: 1234}},
			}, outSpans)
		})
	}

}
