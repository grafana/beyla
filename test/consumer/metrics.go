package consumer

import (
	"bytes"
	"context"
	"net/http"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
)

type MockMetricsConsumer struct {
	Endpoint string
	consumer.Metrics
}

// ConsumerMetrics implements the consumer.Metrics interface, sends pdata.Metrics to the collector
// specified in the endpoint.
func (m *MockMetricsConsumer) ConsumeMetrics(_ context.Context, md pmetric.Metrics) error {
	req := pmetricotlp.NewExportRequestFromMetrics(md)
	body, err := req.MarshalProto()
	if err != nil {
		return err
	}
	_, err = http.Post(m.Endpoint+"/v1/metrics", "application/x-protobuf", bytes.NewReader(body))
	if err != nil {
		return err
	}
	return nil
}
