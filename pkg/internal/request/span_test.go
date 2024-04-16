package request

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSpanClientServer(t *testing.T) {
	for _, st := range []EventType{EventTypeHTTP, EventTypeGRPC} {
		span := &Span{
			Type: st,
		}
		assert.False(t, span.IsClientSpan())
	}

	for _, st := range []EventType{EventTypeHTTPClient, EventTypeGRPCClient, EventTypeSQLClient} {
		span := &Span{
			Type: st,
		}
		assert.True(t, span.IsClientSpan())
	}
}
