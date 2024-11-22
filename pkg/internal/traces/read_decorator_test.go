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
		desc             string
		cfg              ReadDecorator
		expectedInstance string
		expectedHN       string
	}
	for _, tc := range []testCase{{
		desc:             "dns",
		cfg:              ReadDecorator{InstanceID: InstanceIDConfig{HostnameDNSResolution: true}},
		expectedInstance: dnsHostname + ":1234",
		expectedHN:       dnsHostname,
	}, {
		desc:             "no-dns",
		expectedInstance: localHostname + ":1234",
		expectedHN:       localHostname,
	}, {
		desc:             "override hostname",
		cfg:              ReadDecorator{InstanceID: InstanceIDConfig{OverrideHostname: "foooo"}},
		expectedInstance: "foooo:1234",
		expectedHN:       "foooo",
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
				{Service: svc.Attrs{UID: svc.UID{Instance: tc.expectedInstance}, HostName: tc.expectedHN},
					Path: "/foo", Pid: request.PidInfo{HostPID: 1234}},
				{Service: svc.Attrs{UID: svc.UID{Instance: tc.expectedInstance}, HostName: tc.expectedHN},
					Path: "/bar", Pid: request.PidInfo{HostPID: 1234}},
			}, outSpans)
		})
	}

}
