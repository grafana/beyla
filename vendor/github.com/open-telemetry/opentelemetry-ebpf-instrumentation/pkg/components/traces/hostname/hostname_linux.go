// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package hostname

import (
	"errors"
	"net"
	"strings"

	"github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/components/helpers"
)

// attempts to determine the hostname, gracefully falling back until we
// run out of options
func internalHostname() (hn string, err error) {
	// attempt to fetch FQDN
	hn, err = helpers.RunCommand("/usr/bin/env", "", "hostname", "-f")
	if err == nil && hn != "" {
		return
	}

	// failing that try the short name
	hn, err = helpers.RunCommand("/usr/bin/env", "", "hostname")
	if err == nil && hn != "" {
		return
	}

	// return whatever we did get including the error
	return
}

// Looks up for the Fully Qualified Domain Name.
// `localhost` should not be returned as FQDN, but until deciding how it affects we will maintain this version
// for linux and windows for backwards compatibility
func getFqdnHostname(osHost string) (string, error) {
	ips, err := net.LookupIP(osHost)
	if err != nil {
		return "", err
	}

	for _, ip := range ips {
		hosts, err := net.LookupAddr(ip.String())
		if err != nil || len(hosts) == 0 {
			continue
		}
		logger().Debug("found FQDN hosts", "hosts", hosts)
		return strings.TrimSuffix(hosts[0], "."), nil
	}
	return "", errors.New("can't lookup FQDN")
}
