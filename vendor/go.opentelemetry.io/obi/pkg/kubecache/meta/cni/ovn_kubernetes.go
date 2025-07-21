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
package cni

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"

	v1 "k8s.io/api/core/v1"
)

const (
	ovnSubnetAnnotation = "k8s.ovn.org/node-subnets"
)

func AddOvnIPs(ips []string, node *v1.Node) []string {
	// Add IP that is used in OVN for some traffic on mp0 interface
	// (no IP / error returned when not using ovn-k)
	ip, err := findOvnMp0IP(node.Annotations)
	if err != nil {
		// Log the error as Info, do not block other ips indexing
		slog.Info("failed to index OVN mp0 IP", "error", err)
	} else if ip != "" {
		return append(ips, ip)
	}
	return ips
}

func findOvnMp0IP(annotations map[string]string) (string, error) {
	if subnetsJSON, ok := annotations[ovnSubnetAnnotation]; ok {
		var subnets map[string]string
		err := json.Unmarshal([]byte(subnetsJSON), &subnets)
		if err != nil {
			return "", fmt.Errorf("cannot read annotation %s: %w", ovnSubnetAnnotation, err)
		}
		if subnet, ok := subnets["default"]; ok {
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
		return "", fmt.Errorf("unexpected content for annotation %s: %s", ovnSubnetAnnotation, subnetsJSON)
	}
	// Annotation not present (expected if not using ovn-kubernetes) => just ignore, no error
	return "", nil
}
