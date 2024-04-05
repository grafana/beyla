// Copyright 2020 New Relic Corporation. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
package hostname

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	fullName     = "myhost.mdydomain.net"
	fullName2    = "changedHost.mdydomain.net"
	shortName    = "myhost"
	shortName2   = "changedHost"
	internalName = "myhost.localdomain"
)

// Fake functions for testing

func workingFull(_ string) (string, error)     { return fullName, nil }
func workingFull2(_ string) (string, error)    { return fullName2, nil }
func failingFull(_ string) (string, error)     { return "", errors.New("catapun") }
func misbehavingFull(_ string) (string, error) { return "", nil } // Doesn't fail but returns empty hostname
func workingShort() (string, error)            { return shortName, nil }
func workingShort2() (string, error)           { return shortName2, nil }
func failingShort() (string, error)            { return "", errors.New("patapam") }
func misbehavingShort() (string, error)        { return "", nil } // Doesn't fail but returns empty hostname
func localhostFull(_ string) (string, error)   { return "localhost", nil }
func localhostShort() (string, error)          { return "localhost", nil }
func internalFull() (string, error)            { return fullName, nil }
func internal() (string, error)                { return internalName, nil }

// Actual tests

func TestHostnameResolver_Update(t *testing.T) {
	// Given a Hostname Resolver
	resolver := fallbackResolver{full: workingFull, internal: internal, short: workingShort}

	// That has correctly resolved the hostnames
	full, short, err := resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, fullName, full)
	assert.Equal(t, shortName, short)

	// When the hostname changes
	resolver.full = workingFull2
	resolver.short = workingShort2

	// The hostname query return the hostnames
	full, short, err = resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, fullName2, full)
	assert.Equal(t, shortName2, short)
}

func TestHostnameResolver_FullFails(t *testing.T) {
	// Given a Hostname Resolver whose full name can't be resolved
	resolver := fallbackResolver{full: failingFull, internal: failingShort, short: workingShort}

	// When the names are queried
	full, short, err := resolver.Query()
	// The short name is fallen back as full name
	assert.NoError(t, err)
	assert.Equal(t, shortName, full)
	assert.Equal(t, shortName, short)

	// When the problem is resolved
	resolver.full = workingFull

	// The hostname query return the real full hostname
	full, short, err = resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, fullName, full)
	assert.Equal(t, shortName, short)

	// And if the full name doesn't work again
	resolver.full = failingFull

	// The stored full hostname is returned anyway
	full, short, err = resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, fullName, full)
	assert.Equal(t, shortName, short)
}

func TestHostnameResolver_FullFailsFallingBackInInternal(t *testing.T) {
	// Given a Hostname Resolver whose full name can't be resolved
	resolver := fallbackResolver{full: failingFull, internal: internal, short: workingShort}

	// When the names are queried
	full, short, err := resolver.Query()
	// The internal name is fallen back as full name
	assert.NoError(t, err)
	assert.Equal(t, internalName, full)
	assert.Equal(t, shortName, short)

	// When the problem is resolved
	resolver.full = workingFull

	// The hostname query return the real full hostname
	full, short, err = resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, fullName, full)
	assert.Equal(t, shortName, short)

	// And if the full name doesn't work again
	resolver.full = failingFull

	// The stored full hostname is returned anyway
	full, short, err = resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, fullName, full)
	assert.Equal(t, shortName, short)

	// But if the full changes after bringing back to life
	resolver.full = workingFull2

	// The full hostname is updated
	full, short, err = resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, fullName2, full)
	assert.Equal(t, shortName, short)
}

func TestHostnameResolver_FullIsLocalhost(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name string
	}{
		{
			name: "localhost",
		},
		{
			name: "ip6-localhost",
		},
		{
			name: "ipv6-localhost",
		},
		{
			name: "ip6-loopback",
		},
		{
			name: "ipv6-loopback",
		},
	}
	for i := range testCases {
		testCase := testCases[i]
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			// Given a Hostname Resolver that resolves "localhost" as full hostname
			fullResolver := func(_ string) (string, error) { return testCase.name, nil }
			resolver := fallbackResolver{full: fullResolver, short: workingShort, internal: internalFull}

			// When the names are queried
			full, short, err := resolver.Query()
			// The internal kernel name is fallen back as full name
			assert.NoError(t, err)
			assert.Equal(t, fullName, full)
			assert.Equal(t, shortName, short)

			// And if the full name stop working
			resolver.full = failingFull

			// The stored full kernel hostname is returned anyway
			full, short, err = resolver.Query()
			assert.NoError(t, err)
			assert.Equal(t, fullName, full)
			assert.Equal(t, shortName, short)
		})
	}
}

func TestHostnameResolver_FullAndInternalAreLocalhost(t *testing.T) {
	// Given a Hostname Resolver that resolves "localhost" as full hostname
	resolver := fallbackResolver{full: localhostFull, short: workingShort, internal: localhostShort}

	// When the names are queried
	full, short, err := resolver.Query()
	// The short name is fallen back as full name
	assert.NoError(t, err)
	assert.Equal(t, shortName, full)
	assert.Equal(t, shortName, short)

	// And if the full name stop working
	resolver.full = failingFull

	// The short hostname is returned anyway
	full, short, err = resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, shortName, full)
	assert.Equal(t, shortName, short)

	// And when the internal full name starts working
	resolver.internal = internal

	// The stored full kernel hostname is returned
	full, short, err = resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, internalName, full)
	assert.Equal(t, shortName, short)

	// And when the full hostname starts working
	resolver.full = workingFull

	// The full hostname is returned
	full, short, err = resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, fullName, full)
	assert.Equal(t, shortName, short)
}

func TestHostnameResolver_FailureOnFistInvocation(t *testing.T) {
	tests := []struct {
		name          string
		fqdn          func(string) (string, error)
		os            func() (string, error)
		expectedFull  string
		expectedShort string
		expectedError func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool
	}{
		{
			"fails all the hostname resolution",
			failingFull, failingShort, "", "", assert.Error,
		},
		{
			"short hostname fails",
			workingFull, failingShort, "", "", assert.Error,
		},
		{
			"full hostname fails and it provisionally gets the short name as fallback",
			failingFull, workingShort, shortName, shortName, assert.NoError,
		},
		{
			"misbehaving hostname resolution",
			misbehavingFull, misbehavingShort, "", "", assert.Error,
		},
		{
			"short hostname misbehaves",
			workingFull, misbehavingShort, fullName, "", assert.NoError,
		},
		{
			"full hostname misbehaves and it provisionally gets the short name as fallback",
			misbehavingFull, workingShort, shortName, shortName, assert.NoError,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given a resolver
			resolver := fallbackResolver{short: test.os, internal: failingShort, full: test.fqdn}

			// That fails (total or partially) on the first invocation
			full, short, err := resolver.Query()
			test.expectedError(t, err)
			assert.Equal(t, test.expectedFull, full)
			assert.Equal(t, test.expectedShort, short)

			// When it gets recovered
			resolver.full = workingFull2
			resolver.short = workingShort2

			// The hostname query return the hostnames
			full, short, err = resolver.Query()
			assert.NoError(t, err)
			assert.Equal(t, fullName2, full)
			assert.Equal(t, shortName2, short)
		})
	}
}

func TestHostnameResolver_FailureRelyingOnCachedValues(t *testing.T) {
	tests := []struct {
		name string
		fqdn func(string) (string, error)
		os   func() (string, error)
	}{
		{"fails all the hostname resolution", failingFull, failingShort},
		{"short hostname fails", workingFull, failingShort},
		{"full hostname fails", failingFull, workingShort},
		{"misbehaving all the hostname resolution", misbehavingFull, misbehavingShort},
		{"short hostname misbehaving", workingFull, misbehavingShort},
		{"full hostname misbehaving", misbehavingFull, workingShort},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given a Hostname Resolver
			resolver := fallbackResolver{full: workingFull, internal: internal, short: workingShort}

			// That has correctly resolved the hostnames
			full, short, err := resolver.Query()
			assert.NoError(t, err)
			assert.Equal(t, fullName, full)
			assert.Equal(t, shortName, short)

			// When it fails
			resolver.full = test.fqdn
			resolver.short = test.os

			// The hostname query return the cached hostnames
			full, short, err = resolver.Query()
			assert.NoError(t, err)
			assert.Equal(t, fullName, full)
			assert.Equal(t, shortName, short)
		})
	}
}

func TestDNSResolver(t *testing.T) {
	// invoking a New Hostname Resolver without any overriding configuration
	resolver := CreateResolver("", "", true)

	// resolves host names to some non-null hostnames
	full, short, err := resolver.Query()
	assert.NoError(t, err)
	assert.NotEmpty(t, full)
	assert.NotEmpty(t, short)
}

func TestDNSResolver_Override(t *testing.T) {
	// invoking a New Hostname Resolver without any overriding configuration
	resolver := CreateResolver("my-hostname.host.com", "my-hostname", true)

	// resolves host names to the overridden hostnames
	full, short, err := resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, "my-hostname.host.com", full)
	assert.Equal(t, "my-hostname", short)
}

func TestDNSResolver_OverrideLocalhost(t *testing.T) {
	// invoking a New Hostname Resolver overridden with a non-recommended host name
	resolver := CreateResolver("localhost", "", true)

	// anyway resolves host names to the overridden hostname
	full, short, err := resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, "localhost", full)
	assert.NotEmpty(t, short)
}

func TestInternalResolver(t *testing.T) {
	// invoking a New Hostname Resolver without any overriding configuration
	resolver := CreateResolver("", "", false)

	// resolves host names to some non-null hostnames
	full, short, err := resolver.Query()
	assert.NoError(t, err)
	assert.NotEmpty(t, full)
	assert.NotEmpty(t, short)
}

func TestInternalResolver_Override(t *testing.T) {
	// invoking a New Hostname Resolver without any overriding configuration
	resolver := CreateResolver("my-hostname.host.com", "my-hostname", false)

	// resolves host names to the overridden hostnames
	full, short, err := resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, "my-hostname.host.com", full)
	assert.Equal(t, "my-hostname", short)
}

func TestInternalResolver_OverrideLocalhost(t *testing.T) {
	// invoking a New Hostname Resolver overridden with a non-recommended host name
	resolver := CreateResolver("localhost", "", false)

	// anyway resolves host names to the overridden hostname
	full, short, err := resolver.Query()
	assert.NoError(t, err)
	assert.Equal(t, "localhost", full)
	assert.NotEmpty(t, short)
}

func TestFallbackResolver_LongTriggersResolution(t *testing.T) {
	resolver := CreateResolver("", "", false)

	assert.NotEmpty(t, resolver.Long())
}
