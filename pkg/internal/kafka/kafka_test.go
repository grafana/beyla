package kafka

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsKafkaRequest(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *Info
	}{
		{
			name:  "Fetch request",
			input: []byte{0, 0, 0, 94, 0, 1, 0, 11, 0, 0, 0, 224, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 6, 64, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: &Info{
				ClientID:    "sarama",
				Operation:   Fetch,
				Topic:       "important",
				TopicOffset: 45,
			},
		},
		{
			name:  "Produce request",
			input: []byte{0, 0, 0, 123, 0, 0, 0, 7, 0, 0, 0, 2, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 39, 16, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0, 0, 2, 249, 236, 167, 144, 0, 0, 0, 0, 0, 0, 0, 0, 1, 143, 191, 130, 165, 117, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 1, 20, 0, 0, 0, 1, 8, 100, 97, 116, 97, 0},
			expected: &Info{
				ClientID:    "sarama",
				Operation:   Produce,
				Topic:       "important",
				TopicOffset: 28,
			},
		},
		{
			name:     "Invalid request",
			input:    []byte{0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 2, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 39, 16, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 72},
			expected: &Info{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _ := ProcessKafkaData(tt.input)
			assert.Equal(t, tt.expected, res)
		})
	}
}

func TestGetTopicOffsetFromProduceOperation(t *testing.T) {
	header := &Header{
		APIVersion: 3,
	}
	pkt := []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	offset := 0

	success, err := getTopicOffsetFromProduceOperation(header, pkt, &offset)

	assert.True(t, success)
	assert.NoError(t, err)
	assert.Equal(t, 10, offset)

	header.APIVersion = 2
	pkt = []byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	offset = 0

	success, err = getTopicOffsetFromProduceOperation(header, pkt, &offset)

	assert.False(t, success)
	assert.NoError(t, err)
	assert.Equal(t, 0, offset)

	pkt = []byte{0x00}
	offset = 0

	success, err = getTopicOffsetFromProduceOperation(header, pkt, &offset)

	assert.False(t, success)
	assert.Error(t, err)
	assert.Equal(t, 0, offset)
}

func TestGetTopicOffsetFromFetchOperation(t *testing.T) {
	header := &Header{
		APIVersion: 3,
	}

	offset := getTopicOffsetFromFetchOperation(header)
	expectedOffset := 3*4 + 4
	assert.Equal(t, expectedOffset, offset)

	header.APIVersion = 4
	offset = getTopicOffsetFromFetchOperation(header)
	expectedOffset = 3*4 + 5
	assert.Equal(t, expectedOffset, offset)

	header.APIVersion = 7
	offset = getTopicOffsetFromFetchOperation(header)
	expectedOffset = 3*4 + 4 + 1 + 2*4
	assert.Equal(t, expectedOffset, offset)

	header.APIVersion = 2
	offset = getTopicOffsetFromFetchOperation(header)
	expectedOffset = 3 * 4
	assert.Equal(t, expectedOffset, offset)
}

func TestIsValidKafkaHeader(t *testing.T) {
	header := &Header{
		MessageSize:   100,
		APIVersion:    3,
		APIKey:        1,
		CorrelationID: 123,
		ClientIDSize:  0,
	}

	result := isValidKafkaHeader(header)
	assert.True(t, result)

	header.MessageSize = 10
	result = isValidKafkaHeader(header)
	assert.False(t, result)

	header.MessageSize = 100
	header.APIVersion = -1
	result = isValidKafkaHeader(header)
	assert.False(t, result)

	header.APIVersion = 3
	header.APIKey = 2
	result = isValidKafkaHeader(header)
	assert.False(t, result)

	header.APIKey = 1
	header.CorrelationID = -1
	result = isValidKafkaHeader(header)
	assert.False(t, result)

	header.CorrelationID = 123
	header.ClientIDSize = -2
	result = isValidKafkaHeader(header)
	assert.False(t, result)
}
