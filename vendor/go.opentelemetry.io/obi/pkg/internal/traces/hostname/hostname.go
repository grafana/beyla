// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package hostname // import "go.opentelemetry.io/obi/pkg/internal/traces/hostname"

import (
	"errors"
	"log/slog"
	"os"
)

var fullHostnameResolver = getFqdnHostname

func logger() *slog.Logger {
	return slog.With("component", "HostnameResolver")
}

// Resolver provides full name resolving functionalities
type Resolver interface {
	// Query returns the full hostname, or error if the process has not been completed
	Query() (string, error)
}

// CreateResolver creates a HostnameResolver.
// If overrideFull is not an empty string, the hostname won't resolve automatically but will use
// the passed values.
// If dnsResolution is true, returns a HostnameResolver that attempts to resolve the Fully Qualified Domain Name
// as the full hostname.
// If dnsResolution is false, returns a HostnameResolver resolves internally the full hostname (asking to the OS for it).
// If the full hostname resolution process fails (e.g. due to a temporary DNS failure), it
// returns the previous successful resolution (or the short hostname if it has never worked
// previously).
func CreateResolver(overrideFull string, dnsResolution bool) Resolver {
	var resolver *fallbackResolver
	if dnsResolution {
		resolver = newDNSResolver(overrideFull)
	} else {
		resolver = newInternalResolver(overrideFull)
	}
	resolver.short = os.Hostname
	return resolver
}

func newDNSResolver(overrideFull string) *fallbackResolver {
	return &fallbackResolver{
		full:           fullHostnameResolver,
		internal:       internalHostname,
		overriddenFull: overrideFull,
	}
}

func newInternalResolver(overrideFull string) *fallbackResolver {
	fullResolver := func(_ string) (string, error) {
		return internalHostname()
	}
	internalResolver := func() (string, error) {
		// after fullResolver has failed, this will make the fallback resolver to use the last successful resolution
		return "", errors.New("internal hostname resolution did not work")
	}
	return &fallbackResolver{
		internal:       internalResolver,
		full:           fullResolver,
		overriddenFull: overrideFull,
	}
}

// Implementation of the HostnameResolver interface that provides fallback capabilities
// in case the full name resolving fails, returning the last successful value.
// If the Full name resolution is "localhost" (known problem in some wrong FQDN configurations)
// the "internal" name resolver is applied.
type fallbackResolver struct {
	overriddenFull string
	short          func() (string, error)
	internal       func() (string, error)
	full           func(string) (string, error)
}

// Query returns the full and the short host name, or error if none of both can't be returned.
// This implementation assumes the full host name may fail since it can depend on an external
// Query returns the full hostname, or an error if no hostname can be resolved.
// If full hostname resolution fails or returns a localhost name, it falls back
// to the internal hostname and then the short hostname.
func (r *fallbackResolver) Query() (string, error) {
	if r.overriddenFull != "" {
		return r.overriddenFull, nil
	}
	log := logger()
	short, err := r.short()
	if err != nil {
		log.Debug("failed to resolve short hostname", "error", err)
	}
	full, err := r.full(short)
	if err != nil {
		log.Debug("failed to resolve full hostname", "error", err)
	}
	if full == "" || isLocalhost(full) {
		full, err = r.internal()
		if err != nil {
			log.Debug("internal hostname resolution failed", "error", err)
			full = short
		}
		if isLocalhost(full) {
			if isLocalhost(short) {
				full = ""
			} else {
				full = short
			}
		}
	}
	if full == "" {
		return "", errors.New("can't resolve either full or short hostname")
	}
	return full, nil
}

func isLocalhost(name string) bool {
	switch name {
	case "localhost", "ip6-localhost", "ip6-loopback", "ipv6-localhost", "ipv6-loopback": //nolint:goconst
		return true
	}
	return false
}
