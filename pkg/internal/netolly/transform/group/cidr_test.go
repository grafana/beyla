package group

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPGrouper(t *testing.T) {
	g, err := newIPGrouper(&Group{CIDR: []string{
		"10.0.0.0/8",
		"10.1.2.0/24",
		"140.130.22.0/24",
		"2001:db8:3c4d:15::/64",
		"2001::/16",
	}})
	require.NoError(t, err)

	assert.Equal(t, "10.0.0.0/8", g.CIDR(net.ParseIP("10.3.4.5")))
	assert.Equal(t, "10.1.2.0/24", g.CIDR(net.ParseIP("10.1.2.3")))
	assert.Equal(t, "2001:db8:3c4d:15::/64", g.CIDR(net.ParseIP("2001:db8:3c4d:15:3210::")))
	assert.Equal(t, "2001::/16", g.CIDR(net.ParseIP("2001:3333:3333::")))
	assert.Equal(t, "140.130.22.0/24", g.CIDR(net.ParseIP("140.130.22.11")))

	assert.Empty(t, g.CIDR(net.ParseIP("140.130.23.11")))
	assert.Empty(t, g.CIDR(net.ParseIP("180.130.22.11")))
}
