package otel

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
)

func newSpanWithAttrs(traces ptrace.Traces, set func(s ptrace.Span)) ptrace.Span {
	s := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	if set != nil {
		set(s)
	}
	return s
}

func TestStampSigilAttributes_GenerationID(t *testing.T) {
	traces := ptrace.NewTraces()
	s1 := newSpanWithAttrs(traces, nil)
	s2 := newSpanWithAttrs(traces, nil)

	stampSigilRequiredAttributes(traces)

	v1, ok := s1.Attributes().Get(sigilGenerationIDKey)
	assert.True(t, ok)
	assert.True(t, strings.HasPrefix(v1.Str(), "gen_"))

	v2, ok := s2.Attributes().Get(sigilGenerationIDKey)
	assert.True(t, ok)
	assert.True(t, strings.HasPrefix(v2.Str(), "gen_"))

	// each span gets its own fresh UUID
	assert.NotEqual(t, v1.Str(), v2.Str())
}

func TestStampSigilAttributes_ConversationBackfill(t *testing.T) {
	traces := ptrace.NewTraces()

	// has response id, missing conversation id -> backfilled
	backfilled := newSpanWithAttrs(traces, func(s ptrace.Span) {
		s.Attributes().PutStr(string(semconv.GenAIResponseIDKey), "resp-123")
	})
	// has both -> conversation id left untouched
	preserved := newSpanWithAttrs(traces, func(s ptrace.Span) {
		s.Attributes().PutStr(string(semconv.GenAIResponseIDKey), "resp-456")
		s.Attributes().PutStr(string(semconv.GenAIConversationIDKey), "conv-existing")
	})
	// no response id -> no conversation id added
	untouched := newSpanWithAttrs(traces, nil)

	stampSigilRequiredAttributes(traces)

	conv, ok := backfilled.Attributes().Get(string(semconv.GenAIConversationIDKey))
	assert.True(t, ok)
	assert.Equal(t, "resp-123", conv.Str())

	conv, ok = preserved.Attributes().Get(string(semconv.GenAIConversationIDKey))
	assert.True(t, ok)
	assert.Equal(t, "conv-existing", conv.Str())

	_, ok = untouched.Attributes().Get(string(semconv.GenAIConversationIDKey))
	assert.False(t, ok)
}
