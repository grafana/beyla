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
		desc        string
		cfg         ReadDecorator
		expectedUID svc.UID
		expectedHN  string
	}
	for _, tc := range []testCase{{
		desc:        "dns",
		cfg:         ReadDecorator{InstanceID: InstanceIDConfig{HostnameDNSResolution: true}},
		expectedUID: svc.NewUID(dnsHostname).AppendUint32(1234),
		expectedHN:  dnsHostname,
	}, {
		desc:        "no-dns",
		expectedUID: svc.NewUID(localHostname).AppendUint32(1234),
		expectedHN:  localHostname,
	}, {
		desc:        "override hostname",
		cfg:         ReadDecorator{InstanceID: InstanceIDConfig{OverrideHostname: "foooo"}},
		expectedUID: svc.NewUID("foooo").AppendUint32(1234),
		expectedHN:  "foooo",
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			cfg := tc.cfg
			rawInput := make(chan []request.Span, 10)
			decoratedOutput := make(chan []request.Span, 10)
			cfg.TracesInput = rawInput
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			readLoop := ReadFromChannel(ctx, &cfg)
			go readLoop(decoratedOutput)
			rawInput <- []request.Span{
				{Path: "/foo", Pid: request.PidInfo{HostPID: 1234}},
				{Path: "/bar", Pid: request.PidInfo{HostPID: 1234}},
			}
			outSpans := testutil.ReadChannel(t, decoratedOutput, testTimeout)
			assert.Equal(t, []request.Span{
				{ServiceID: svc.ID{UID: tc.expectedUID, HostName: tc.expectedHN},
					Path: "/foo", Pid: request.PidInfo{HostPID: 1234}},
				{ServiceID: svc.ID{UID: tc.expectedUID, HostName: tc.expectedHN},
					Path: "/bar", Pid: request.PidInfo{HostPID: 1234}},
			}, outSpans)
		})
	}

}
