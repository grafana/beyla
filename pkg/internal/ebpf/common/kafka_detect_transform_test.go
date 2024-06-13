package ebpfcommon

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProcessKafkaRequest(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected *KafkaInfo
	}{
		{
			name:  "Fetch request (v11)",
			input: []byte{0, 0, 0, 94, 0, 1, 0, 11, 0, 0, 0, 224, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 6, 64, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: &KafkaInfo{
				ClientID:    "sarama",
				Operation:   Fetch,
				Topic:       "important",
				TopicOffset: 45,
			},
		},
		{
			name:  "Fetch request (v12)",
			input: []byte{0, 0, 0, 52, 0, 1, 0, 12, 0, 0, 1, 3, 0, 12, 99, 111, 110, 115, 117, 109, 101, 114, 45, 49, 45, 49, 0, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 30, 37, 158, 231, 0, 0, 0, 156, 1, 1, 1, 0, 53, 99, 48, 57, 45, 52, 52, 48, 48, 45, 98, 54, 101, 101, 45, 56, 54, 102, 97, 102, 101, 102, 57, 52, 102, 101, 98, 0, 2, 9, 109, 121, 45, 116, 111, 112, 105, 99, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 100, 0, 0, 0, 0, 1, 0, 0, 0, 101, 121, 12, 118, 97, 108, 117, 101, 51, 0, 30, 0, 0},
			expected: &KafkaInfo{
				ClientID:    "consumer-1-1",
				Operation:   Fetch,
				Topic:       "my-topic",
				TopicOffset: 51,
			},
		},
		{
			name:  "Fetch request (v15)",
			input: []byte{0, 0, 0, 68, 0, 1, 0, 15, 0, 0, 38, 94, 0, 32, 99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 100, 101, 116, 101, 99, 116, 105, 111, 110, 115, 101, 114, 118, 105, 99, 101, 45, 49, 0, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 33, 62, 224, 94, 0, 0, 30, 44, 1, 1, 1, 0, 1, 70, 99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 100, 101, 116, 101, 99, 116, 105, 111, 110, 115, 101, 114, 118, 105, 99, 101, 45, 49, 45, 50, 51, 48, 98, 51, 55, 101, 100, 45, 98, 101, 57, 102, 45, 52, 97, 53, 99, 45, 97, 52},
			expected: &KafkaInfo{
				ClientID:    "consumer-frauddetectionservice-1",
				Operation:   Fetch,
				Topic:       "*",
				TopicOffset: 67,
			},
		},
		{
			name:  "Produce request (v7)",
			input: []byte{0, 0, 0, 123, 0, 0, 0, 7, 0, 0, 0, 2, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 39, 16, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 72, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0, 0, 2, 249, 236, 167, 144, 0, 0, 0, 0, 0, 0, 0, 0, 1, 143, 191, 130, 165, 117, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 1, 20, 0, 0, 0, 1, 8, 100, 97, 116, 97, 0},
			expected: &KafkaInfo{
				ClientID:    "sarama",
				Operation:   Produce,
				Topic:       "important",
				TopicOffset: 28,
			},
		},
		{
			name:  "Produce request (v9)",
			input: []byte{0, 0, 0, 124, 0, 0, 0, 9, 0, 0, 0, 8, 0, 10, 112, 114, 111, 100, 117, 99, 101, 114, 45, 49, 0, 0, 0, 1, 0, 0, 117, 48, 2, 9, 109, 121, 45, 116, 111, 112, 105, 99, 2, 0, 0, 0, 0, 78, 103, 0, 0, 0, 1, 2, 0, 0, 9, 109, 121, 45, 116, 111, 112, 105, 99, 193, 136, 51, 44, 67, 57, 71, 124, 178, 93, 33, 21, 191, 31, 138, 233, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 1, 2, 0, 0, 0, 1, 1, 0, 128, 0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 16, 0, 0, 0, 4, 0, 0, 17},
			expected: &KafkaInfo{
				ClientID:    "producer-1",
				Operation:   Produce,
				Topic:       "my-topic",
				TopicOffset: 28,
			},
		},
		{
			name:     "Invalid request",
			input:    []byte{0, 0, 0, 1, 0, 0, 0, 7, 0, 0, 0, 2, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 39, 16, 0, 0, 0, 1, 0, 9, 105, 109, 112, 111, 114, 116, 97, 110, 116, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 72},
			expected: &KafkaInfo{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, _ := ProcessKafkaRequest(tt.input)
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

func TestReadUnsignedVarint(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected int
		err      error
	}{
		{
			name:     "Valid varint",
			data:     []byte{0x8E, 0x02},
			expected: 270,
			err:      nil,
		},
		{
			name:     "Valid varint with multiple bytes",
			data:     []byte{0x8E, 0x8E, 0x02},
			expected: 34574,
			err:      nil,
		},
		{
			name:     "Illegal varint",
			data:     []byte{0x8E, 0x8E, 0x8E, 0x8E, 0x8E, 0x8E, 0x8E, 0x8E},
			expected: 0,
			err:      errors.New("illegal varint"),
		},
		{
			name:     "Incomplete varint",
			data:     []byte{0x8E},
			expected: 0,
			err:      errors.New("data ended before varint was complete"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := readUnsignedVarint(tt.data)
			assert.Equal(t, tt.expected, result)
			assert.Equal(t, tt.err, err)
		})
	}
}

func TestExtractTopic(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		output string
	}{
		{
			name:   "Valid topic",
			input:  "c09-4400-b6ee-86fafef94feb\x00\x02\tmy-topic\x02\x00\x00\x00\x00\x00\x00",
			output: "my-topic",
		},
		{
			name:   "Valid topic (without uuid)",
			input:  "\x00\x02\tmy_topic\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x00\x00",
			output: "my_topic",
		},
		{
			name:   "Invalid format (without \t)",
			input:  "\x00\x02my_topic\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00d\x00\x00",
			output: "",
		},
		{
			name:   "Invalid format (without \x02)",
			input:  "\x00\tmy_topic\x00\x00\x00\x00\x00\x00\x00\x00",
			output: "",
		},
		{
			name:   "No topic",
			input:  "\x02\t\x02",
			output: "",
		},
		{
			name:   "Invalid input",
			input:  "invalid",
			output: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTopic(tt.input)
			assert.Equal(t, tt.output, result)
		})
	}
}
