// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/obi/pkg/config"

// InstanceIDConfig configures how OBI will get the Instance ID of the traces/metrics
// from the current hostname + the instrumented process PID
type InstanceIDConfig struct {
	// HostnameDNSResolution is true if OBI uses the DNS to resolve the local hostname or
	// false if it uses the local hostname.
	HostnameDNSResolution bool `yaml:"dns" env:"OTEL_EBPF_HOSTNAME_DNS_RESOLUTION"`
	// OverrideHostname can be optionally set to avoid resolving any hostname and using this
	// value. OBI will anyway attach the process ID to the given hostname for composing
	// the instance ID.
	OverrideHostname string `yaml:"override_hostname" env:"OTEL_EBPF_HOSTNAME"`
}
