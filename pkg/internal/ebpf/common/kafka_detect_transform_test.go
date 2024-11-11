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
			name:  "Fetch request (v11) truncated - 1",
			input: []byte{0, 0, 0, 94, 0, 1, 0, 11, 0, 0, 0, 224, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 6, 64, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 1, 0},
			expected: &KafkaInfo{
				ClientID:    "sarama",
				Operation:   Fetch,
				TopicOffset: 45,
			},
		},
		{
			name:  "Fetch request (v11) truncated",
			input: []byte{0, 0, 0, 94, 0, 1, 0, 11, 0, 0, 0, 224, 0, 6, 115, 97, 114, 97, 109, 97, 255, 255, 255, 255, 0, 0, 1, 244, 0, 0, 0, 1, 6, 64, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255, 0, 0, 0, 1},
			expected: &KafkaInfo{
				ClientID:    "sarama",
				Operation:   Fetch,
				TopicOffset: 45,
			},
		},
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
		{
			name:     "Redis request",
			input:    []byte{42, 51, 13, 10, 36, 52, 13, 10, 72, 71, 69, 84, 13, 10, 36, 51, 54, 13, 10, 56, 97, 100, 48, 101, 56, 99, 97, 45, 101, 97, 49, 57, 45, 52, 50, 97, 57, 45, 98, 51, 55, 48, 45, 98, 99, 97, 102, 102, 50, 55, 54, 55, 98, 56, 54, 13, 10, 36, 52, 13, 10, 99, 97, 114, 116, 13, 10, 103, 58, 32, 34, 51, 49, 117, 50, 107, 97, 100, 98, 108, 113, 53, 106, 34, 13, 10, 99, 111, 110, 116, 101, 110, 116, 45, 108, 101, 110, 103, 116, 104, 58, 32, 49, 57, 57, 13, 10, 118, 97, 114, 121, 58, 32, 65, 99, 99, 101, 112, 116, 45, 69, 110, 99, 111, 100, 105, 110, 103, 13, 10, 100, 97, 116, 101, 58, 32, 87, 101, 100, 44, 32, 48, 51, 32, 74, 117, 108, 32, 50, 48, 50, 52, 32, 49, 55, 58, 52, 54, 58, 49, 55, 32, 71, 77, 84, 13, 10, 120, 45, 101, 110, 118, 111, 121, 45, 117, 112, 115, 116, 114, 101, 97, 109, 45, 115, 101, 114, 118, 105, 99, 101, 45, 116, 105, 109, 101, 58, 32, 51, 13, 10, 115, 101, 114, 118, 101, 114, 58, 32, 101, 110, 118, 111, 121, 13, 10, 13, 10, 91, 34, 90, 65, 82, 34, 44, 34, 73, 83, 75, 34, 44, 34, 73, 76, 83, 34, 44, 34, 82, 79, 78, 34, 44, 34, 71, 66, 80, 34, 44, 34, 66, 82, 76, 34, 44, 34},
			expected: &KafkaInfo{},
		},
		{
			name:     "Redis request 2",
			input:    []byte{36, 45, 49, 13, 10, 1, 0, 15, 0, 3, 89, 130, 0, 32, 99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 100, 101, 116, 101, 99, 116, 105, 111, 110, 115, 101, 114, 118, 105, 99, 101, 45, 49, 0, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 17, 170, 173, 222, 0, 0, 141, 2, 1, 1, 1, 0, 101, 112, 116, 45, 114, 97, 110, 103, 101, 115, 58, 32, 98, 121, 116, 101, 115, 13, 10, 108, 97, 115, 116, 45, 109, 111, 100, 105, 102, 105, 101, 100, 58, 32, 70, 114, 105, 44, 32, 48, 55, 32, 74, 117, 110, 32, 50, 48, 50, 52, 32, 48, 48, 58, 53, 55}[:5],
			expected: &KafkaInfo{},
		},
		{
			name:     "Redis request 2, mixed up data",
			input:    []byte{36, 45, 49, 13, 10, 1, 0, 15, 0, 3, 89, 130, 0, 32, 99, 111, 110, 115, 117, 109, 101, 114, 45, 102, 114, 97, 117, 100, 100, 101, 116, 101, 99, 116, 105, 111, 110, 115, 101, 114, 118, 105, 99, 101, 45, 49, 0, 0, 0, 1, 244, 0, 0, 0, 1, 3, 32, 0, 0, 0, 17, 170, 173, 222, 0, 0, 141, 2, 1, 1, 1, 0, 101, 112, 116, 45, 114, 97, 110, 103, 101, 115, 58, 32, 98, 121, 116, 101, 115, 13, 10, 108, 97, 115, 116, 45, 109, 111, 100, 105, 102, 105, 101, 100, 58, 32, 70, 114, 105, 44, 32, 48, 55, 32, 74, 117, 110, 32, 50, 48, 50, 52, 32, 48, 48, 58, 53, 55}[:20],
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

	to, err := getTopicOffsetFromFetchOperation([]byte{}, 0, header)
	assert.NoError(t, err)
	expectedOffset := 3*4 + 4
	assert.Equal(t, expectedOffset, to)

	header.APIVersion = 4
	to, err = getTopicOffsetFromFetchOperation([]byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01}, 0, header)
	assert.NoError(t, err)
	expectedOffset = 3*4 + 5
	assert.Equal(t, expectedOffset, to)

	header.APIVersion = 7
	to, err = getTopicOffsetFromFetchOperation([]byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01}, 0, header)
	assert.NoError(t, err)
	expectedOffset = 3*4 + 4 + 1 + 2*4
	assert.Equal(t, expectedOffset, to)

	header.APIVersion = 2
	to, err = getTopicOffsetFromFetchOperation([]byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01}, 0, header)
	assert.NoError(t, err)
	expectedOffset = 3 * 4
	assert.Equal(t, expectedOffset, to)

	// Isolation level is the last byte in the sequence, it can only be 0 and 1, nothing else.
	header.APIVersion = 7
	_, err = getTopicOffsetFromFetchOperation([]byte{0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02}, 0, header)
	assert.Error(t, err)
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
