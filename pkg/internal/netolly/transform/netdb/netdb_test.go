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

package netdb

import (
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testingServicesDB() (*ServiceNames, error) {
	etcProtos, err := os.Open(path.Join("testdata", "etcProtocols.txt"))
	if err != nil {
		return nil, err
	}
	defer etcProtos.Close()
	etcSvcs, err := os.Open(path.Join("testdata", "etcServices.txt"))
	if err != nil {
		return nil, err
	}
	defer etcSvcs.Close()

	return LoadServicesDB(etcProtos, etcSvcs)
}

func TestServicesDB(t *testing.T) {
	db, err := testingServicesDB()
	require.NoError(t, err)

	assert.Equal(t, "netbios-dgm", db.ByPortAndProtocolNumber(138, 6))
	assert.Equal(t, "netbios-dgm", db.ByPortAndProtocolName(138, "tcp"))
	// verify it also finds service name by protocol alias
	assert.Equal(t, "netbios-dgm", db.ByPortAndProtocolName(138, "TCP"))

	// verify multiple protocols can be associated to the same port
	assert.Equal(t, "ms-sql-s", db.ByPortAndProtocolNumber(1433, 6))
	assert.Equal(t, "ms-sql-s", db.ByPortAndProtocolName(1433, "tcp"))
	assert.Equal(t, "ms-sql-s", db.ByPortAndProtocolName(1433, "TCP"))
	assert.Equal(t, "ms-sql-s", db.ByPortAndProtocolNumber(1433, 17))
	assert.Equal(t, "ms-sql-s", db.ByPortAndProtocolName(1433, "udp"))
	assert.Equal(t, "ms-sql-s", db.ByPortAndProtocolName(1433, "UDP"))

	// verify it does search only by port number, if the protocol does not exist
	assert.Equal(t, "ms-sql-s", db.ByPortAndProtocolNumber(1433, 99999))
	assert.Equal(t, "ms-sql-s", db.ByPortAndProtocolName(1433, "tralara"))

	// verify it returns nothing if the protocol exist but it's not associated to that port
	assert.Empty(t, db.ByPortAndProtocolNumber(1433, 18))
	assert.Empty(t, db.ByPortAndProtocolName(1433, "mux"))
	assert.Empty(t, db.ByPortAndProtocolName(1433, "MUX"))
}

func BenchmarkGetProtoByNumber(b *testing.B) {
	b.StopTimer()
	db, err := testingServicesDB()
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		db.ByPortAndProtocolNumber(80, 6)
		db.ByPortAndProtocolNumber(443, 17)
		db.ByPortAndProtocolNumber(3306, 17)
		db.ByPortAndProtocolNumber(27017, 6)
	}
}

func BenchmarkGetProtoByName(b *testing.B) {
	b.StopTimer()
	db, err := testingServicesDB()
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		db.ByPortAndProtocolName(80, "tcp")
		db.ByPortAndProtocolName(443, "udp")
		db.ByPortAndProtocolName(3306, "UDP")
		db.ByPortAndProtocolName(27017, "TCP")
	}
}
