package instrumentations

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInstrumentationSelection(t *testing.T) {
	is := NewInstrumentationSelection([]string{"http", "sql", "redis"})
	assert.True(t, is.HTTPEnabled())
	assert.True(t, is.SQLEnabled())
	assert.True(t, is.DBEnabled())
	assert.True(t, is.RedisEnabled())
	assert.False(t, is.GRPCEnabled())
	assert.False(t, is.KafkaEnabled())
	assert.False(t, is.MQEnabled())

	is = NewInstrumentationSelection([]string{"grpc", "kafka"})
	assert.False(t, is.HTTPEnabled())
	assert.False(t, is.SQLEnabled())
	assert.False(t, is.DBEnabled())
	assert.False(t, is.RedisEnabled())
	assert.True(t, is.GRPCEnabled())
	assert.True(t, is.KafkaEnabled())
	assert.True(t, is.MQEnabled())
}

func TestInstrumentationSelection_All(t *testing.T) {
	is := NewInstrumentationSelection([]string{"*"})
	assert.True(t, is.HTTPEnabled())
	assert.True(t, is.SQLEnabled())
	assert.True(t, is.DBEnabled())
	assert.True(t, is.RedisEnabled())
	assert.True(t, is.GRPCEnabled())
	assert.True(t, is.KafkaEnabled())
	assert.True(t, is.MQEnabled())
}

func TestInstrumentationSelection_None(t *testing.T) {
	is := NewInstrumentationSelection(nil)
	assert.False(t, is.HTTPEnabled())
	assert.False(t, is.SQLEnabled())
	assert.False(t, is.DBEnabled())
	assert.False(t, is.RedisEnabled())
	assert.False(t, is.GRPCEnabled())
	assert.False(t, is.KafkaEnabled())
	assert.False(t, is.MQEnabled())
}
