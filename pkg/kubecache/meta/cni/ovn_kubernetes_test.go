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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindOvnMp0IP(t *testing.T) {
	// Annotation not found => no error, no ip
	ip, err := findOvnMp0IP(map[string]string{})
	require.NoError(t, err)
	require.Empty(t, ip)

	// Annotation malformed => error, no ip
	ip, err = findOvnMp0IP(map[string]string{
		ovnSubnetAnnotation: "whatever",
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot read annotation")
	require.Empty(t, ip)

	// IP malformed => error, no ip
	ip, err = findOvnMp0IP(map[string]string{
		ovnSubnetAnnotation: `{"default":"10.129/23"}`,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid CIDR address")
	require.Empty(t, ip)

	// Valid annotation => no error, ip
	ip, err = findOvnMp0IP(map[string]string{
		ovnSubnetAnnotation: `{"default":"10.129.0.0/23"}`,
	})
	require.NoError(t, err)
	require.Equal(t, "10.129.0.2", ip)
}
