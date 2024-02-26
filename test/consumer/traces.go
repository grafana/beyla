package consumer

import (
	"bytes"
	"context"
	"net/http"

	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

type MockTraceConsumer struct {
	Endpoint string
	consumer.Traces
}

// ConsumeTraces implements the consumer.Traces interface, sends pdata.Traces to the collector
// specified in the endpoint.
func (m *MockTraceConsumer) ConsumeTraces(_ context.Context, td ptrace.Traces) error {
	req := ptraceotlp.NewExportRequestFromTraces(td)
	body, err := req.MarshalProto()
	if err != nil {
		return err
	}
	_, err = http.Post(m.Endpoint+"/v1/traces", "application/x-protobuf", bytes.NewReader(body))
	if err != nil {
		return err
	}
	return nil
}
