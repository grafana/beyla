package tools

import (
	"github.com/grafana/beyla/test/integration/components/jaeger"
	"go.opentelemetry.io/otel/attribute"
)

func KeyValueToJaegerTag(kv attribute.KeyValue) jaeger.Tag {
	return jaeger.Tag{
		Key:   string(kv.Key),
		Type:  kv.Value.Type().String(),
		Value: kv.Value.AsInterface(),
	}
}

func KeyValuesToJaegerTags(kvs []attribute.KeyValue) []jaeger.Tag {
	tags := make([]jaeger.Tag, len(kvs))
	for i, kv := range kvs {
		tags[i] = KeyValueToJaegerTag(kv)
	}
	return tags
}
