// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

// Package cni provides utilities
// for working with Container Network Interface (CNI) configurations.
package cni // import "go.opentelemetry.io/obi/pkg/kube/kubecache/meta/cni"

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"

	v1 "k8s.io/api/core/v1"
)

const ovnSubnetAnnotation = "k8s.ovn.org/node-subnets"

// AddOvnIPs adds the OVN mp0 IP to the list of IPs for the given node, if applicable.
func AddOvnIPs(ips []string, node *v1.Node) []string {
	// Add IP that is used in OVN for some traffic on mp0 interface
	// (no IP / error returned when not using ovn-k)
	ip, err := findOvnMp0IP(node.Annotations)
	if err != nil {
		// Log the error and do not block other ips indexing
		slog.Error("failed to index OVN mp0 IP", "error", err)
		return ips
	}
	if ip != "" {
		return append(ips, ip)
	}
	return ips
}

// findOvnMp0IP extracts the OVN mp0 IP from the subnet defined in the node annotations.
// Returns empty string if the annotation is not present (i.e., not using ovn-kubernetes).
// Returns an error if the annotation is malformed.
func findOvnMp0IP(annotations map[string]string) (string, error) {
	// Parsing is based on upstream: https://github.com/ovn-kubernetes/ovn-kubernetes/blob/5d56a53df520a085e629cdc71be092afed9c3f0f/go-controller/pkg/util/subnet_annotations.go#L15-L34
	subnetsJSON, ok := annotations[ovnSubnetAnnotation]
	if !ok {
		// Annotation not present (expected if not using ovn-kubernetes) => just ignore, no error
		return "", nil
	}

	// Try to parse as dual-stack (array) first
	var subnetsDual map[string][]string
	if err := json.Unmarshal([]byte(subnetsJSON), &subnetsDual); err == nil {
		subnets, ok := subnetsDual["default"]
		if !ok || len(subnets) == 0 {
			return "", fmt.Errorf("unexpected content for annotation %s: %s", ovnSubnetAnnotation, subnetsJSON)
		}

		// Use the first IPv4 subnet from the array
		for _, subnet := range subnets {
			ip, err := extractMp0IP(subnet)
			if err != nil {
				return "", fmt.Errorf("cannot parse IP from %s annotation (value: %s): %w", ovnSubnetAnnotation, subnetsJSON, err)
			}
			if ip != "" {
				return ip, nil
			}
			// Try next subnet if current one is not IPv4
		}
		// No IPv4 subnet found in the array
		return "", nil
	}

	// Fall back to single-stack (string) format
	var subnetsSingle map[string]string
	if err := json.Unmarshal([]byte(subnetsJSON), &subnetsSingle); err != nil {
		return "", fmt.Errorf("cannot read annotation %s (value: %s): %w", ovnSubnetAnnotation, subnetsJSON, err)
	}
	subnet, ok := subnetsSingle["default"]
	if !ok {
		return "", fmt.Errorf("unexpected content for annotation %s: %s", ovnSubnetAnnotation, subnetsJSON)
	}
	ip, err := extractMp0IP(subnet)
	if err != nil {
		return "", fmt.Errorf("cannot parse IP from %s annotation (value: %s): %w", ovnSubnetAnnotation, subnetsJSON, err)
	}
	return ip, nil
}

// extractMp0IP extracts the mp0 IP from a subnet CIDR.
// Returns empty string for non-IPv4 subnets.
func extractMp0IP(subnet string) (string, error) {
	// From subnet like 10.128.0.0/23, we want to index IP 10.128.0.2
	ip0, _, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", err
	}
	ip4 := ip0.To4()
	if ip4 == nil {
		// TODO: what's the rule with ipv6?
		return "", nil
	}
	return fmt.Sprintf("%d.%d.%d.2", ip4[0], ip4[1], ip4[2]), nil
}
