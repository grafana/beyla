package transform

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/grafana/beyla/v2/pkg/internal/request"
)

func TestIgnoreMode(t *testing.T) {
	s := request.Span{Path: "/user/1234"}
	setSpanIgnoreMode(IgnoreTraces, &s)
	assert.True(t, s.IgnoreTraces())
	setSpanIgnoreMode(IgnoreMetrics, &s)
	assert.True(t, s.IgnoreMetrics())
}
