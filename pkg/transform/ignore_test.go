package transform

import (
	"testing"

	"github.com/grafana/beyla/v2/pkg/internal/request"
	"github.com/stretchr/testify/assert"
)

func TestIgnoreMode(t *testing.T) {
	s := request.Span{Path: "/user/1234"}
	setSpanIgnoreMode(IgnoreTraces, &s)
	assert.True(t, s.IgnoreTraces())
	setSpanIgnoreMode(IgnoreMetrics, &s)
	assert.True(t, s.IgnoreMetrics())
}
