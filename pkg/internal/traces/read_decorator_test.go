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
		expectedID  string
		expectedUID svc.UID
		expectedHN  string
	}
	for _, tc := range []testCase{{
		desc:        "dns",
		cfg:         ReadDecorator{InstanceID: InstanceIDConfig{HostnameDNSResolution: true}},
		expectedID:  dnsHostname + "-1234",
		expectedUID: svc.UID(dnsHostname + "-1234"),
		expectedHN:  dnsHostname,
	}, {
		desc:        "no-dns",
		expectedID:  localHostname + "-1234",
		expectedUID: svc.UID(localHostname + "-1234"),
		expectedHN:  localHostname,
	}, {
		desc:        "override hostname",
		cfg:         ReadDecorator{InstanceID: InstanceIDConfig{OverrideHostname: "foooo"}},
		expectedID:  "foooo-1234",
		expectedUID: "foooo-1234",
		expectedHN:  "foooo",
	}, {
		desc:       "override HN",
		cfg:        ReadDecorator{InstanceID: InstanceIDConfig{OverrideInstanceID: "instanceee"}},
		expectedID: "instanceee",
		// even if we override instance ID, the UID should be set to a really unique value
		// (same as the automatic instanceID value)
		expectedUID: svc.UID(localHostname + "-1234"),
		expectedHN:  localHostname,
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
				{ServiceID: svc.ID{Instance: tc.expectedID, UID: tc.expectedUID, HostName: tc.expectedHN},
					Path: "/foo", Pid: request.PidInfo{HostPID: 1234}},
				{ServiceID: svc.ID{Instance: tc.expectedID, UID: tc.expectedUID, HostName: tc.expectedHN},
					Path: "/bar", Pid: request.PidInfo{HostPID: 1234}},
			}, outSpans)
		})
	}

}
