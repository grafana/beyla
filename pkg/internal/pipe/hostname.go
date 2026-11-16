// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package pipe

import (
	"errors"
	"net"
	"os"
	"runtime"
	"strings"

	obicfg "go.opentelemetry.io/obi/pkg/config"

	"github.com/grafana/beyla/v3/pkg/internal/helpers"
)

type hostnameResolver struct {
	short    func() (string, error)
	internal func() (string, error)
	fqdn     func(string) (string, error)
}

func nodeHostName(cfg *obicfg.InstanceIDConfig) string {
	resolver := hostnameResolver{short: os.Hostname, internal: internalHostname, fqdn: fqdnHostname}
	return resolver.resolve(cfg)
}

// resolve follows the hostname override and fallback order used by OBI's service instance IDs.
func (r hostnameResolver) resolve(cfg *obicfg.InstanceIDConfig) string {
	if cfg.OverrideHostname != "" {
		return cfg.OverrideHostname
	}
	short, _ := r.short()
	var full string
	if cfg.HostnameDNSResolution {
		full, _ = r.fqdn(short)
	}
	if full == "" || isLocalhost(full) {
		var err error
		full, err = r.internal()
		if err != nil {
			full = short
		}
	}
	if full == "" || isLocalhost(full) {
		full = short
	}
	if isLocalhost(full) {
		return ""
	}
	return full
}

func internalHostname() (string, error) {
	if runtime.GOOS != "linux" {
		return os.Hostname()
	}
	for _, args := range [][]string{{"hostname", "-f"}, {"hostname"}} {
		if name, err := helpers.RunCommand("/usr/bin/env", "", args...); err == nil && name != "" {
			return name, nil
		}
	}
	return "", errors.New("can't resolve internal hostname")
}

func fqdnHostname(short string) (string, error) {
	if runtime.GOOS != "linux" {
		return os.Hostname()
	}
	ips, err := net.LookupIP(short)
	if err != nil {
		return "", err
	}
	for _, ip := range ips {
		if hosts, err := net.LookupAddr(ip.String()); err == nil && len(hosts) > 0 {
			return strings.TrimSuffix(hosts[0], "."), nil
		}
	}
	return "", errors.New("can't resolve FQDN")
}

func isLocalhost(name string) bool {
	switch name {
	case "localhost", "ip6-localhost", "ip6-loopback", "ipv6-localhost", "ipv6-loopback":
		return true
	}
	return false
}
