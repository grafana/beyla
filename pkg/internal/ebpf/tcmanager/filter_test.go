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

package tcmanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInterfaces_DefaultConfig(t *testing.T) {
	ifaces, err := NewInterfaceFilter(nil, []string{"lo"})
	require.NoError(t, err)

	assert.True(t, ifaces.IsAllowed("eth0"))
	assert.True(t, ifaces.IsAllowed("br-0"))
	assert.False(t, ifaces.IsAllowed("lo"))
}

func TestInterfaceFilter_SelectingInterfaces_DefaultExclusion(t *testing.T) {
	ifaces, err := NewInterfaceFilter([]string{"eth0", "/^br-/"}, []string{"lo"})
	require.NoError(t, err)

	assert.True(t, ifaces.IsAllowed("eth0"))
	assert.True(t, ifaces.IsAllowed("br-0"))
	assert.False(t, ifaces.IsAllowed("eth01"))
	assert.False(t, ifaces.IsAllowed("abr-3"))
	assert.False(t, ifaces.IsAllowed("lo"))
}

func TestInterfaceFilter_ExclusionTakesPriority(t *testing.T) {

	ifaces, err := NewInterfaceFilter([]string{"/^eth/", "/^br-/"}, []string{"eth1", "/^br-1/"})
	require.NoError(t, err)

	assert.True(t, ifaces.IsAllowed("eth0"))
	assert.True(t, ifaces.IsAllowed("eth10"))
	assert.True(t, ifaces.IsAllowed("eth11"))
	assert.True(t, ifaces.IsAllowed("br-2"))
	assert.True(t, ifaces.IsAllowed("br-0"))
	assert.False(t, ifaces.IsAllowed("eth1"))
	assert.False(t, ifaces.IsAllowed("br-1"))
	assert.False(t, ifaces.IsAllowed("br-10"))
}
