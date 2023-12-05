package promwrite

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"

	"github.com/prometheus/prometheus/prompb"
)

type TimeSeries struct {
	Labels []Label
	Sample Sample
}

type Label struct {
	Name  string
	Value string
}

type Sample struct {
	Time  time.Time
	Value float64
}

// ClientOption is used to set custom client options.
type ClientOption func(opts *clientOptions)

// HttpClient option allows configuring custom HTTP client.
func HttpClient(client *http.Client) ClientOption {
	return func(opts *clientOptions) {
		opts.httpClient = client
	}
}

type clientOptions struct {
	httpClient *http.Client
}

func NewClient(endpoint string, options ...ClientOption) *Client {
	opts := clientOptions{
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
	for _, opt := range options {
		opt(&opts)
	}
	p := &Client{
		endpoint: endpoint,
		opts:     &opts,
	}
	return p
}

// Client is Prometheus Remote Write client.
type Client struct {
	endpoint string
	opts     *clientOptions
}

type WriteOption func(opts *writeOptions)

// WriteHeaders allows passing custom HTTP headers. Once common use case is to pass `X-Scope-OrgID` header for Cortex tenant.
func WriteHeaders(headers map[string]string) WriteOption {
	return func(opt *writeOptions) {
		opt.headers = headers
	}
}

type writeOptions struct {
	headers map[string]string
}

type WriteRequest struct {
	TimeSeries []TimeSeries
}

type WriteResponse struct {
}

// Write sends HTTP requests to Prometheus Remote Write compatible API endpoint including Prometheus, Cortex and VictoriaMetrics.
func (p *Client) Write(ctx context.Context, req *WriteRequest, options ...WriteOption) (*WriteResponse, error) {
	opts := writeOptions{}
	for _, opt := range options {
		opt(&opts)
	}
	// Marshal proto and compress.
	pbBytes, err := proto.Marshal(&prompb.WriteRequest{
		Timeseries: toProtoTimeSeries(req.TimeSeries),
	})
	if err != nil {
		return nil, fmt.Errorf("promwrite: marshaling remote write request proto: %w", err)
	}

	compressedBytes := snappy.Encode(nil, pbBytes)

	// Prepare http request.
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.endpoint, bytes.NewBuffer(compressedBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Add("X-Prometheus-Remote-Write-Version", "0.1.0")
	httpReq.Header.Add("Content-Encoding", "snappy")
	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	for k, v := range opts.headers {
		httpReq.Header.Add(k, v)
	}

	// Send http request.
	httpResp, err := p.opts.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("promwrite: sending remote write request: %w", err)
	}
	defer httpResp.Body.Close()

	if st := httpResp.StatusCode; st/100 != 2 {
		msg, _ := io.ReadAll(httpResp.Body)
		return nil, &WriteError{
			err:  fmt.Errorf("promwrite: expected status %d, got %d: %s", http.StatusOK, st, string(msg)),
			code: st,
		}
	}
	return &WriteResponse{}, nil
}

func toProtoTimeSeries(timeSeries []TimeSeries) []prompb.TimeSeries {
	res := make([]prompb.TimeSeries, len(timeSeries))
	for i, ts := range timeSeries {
		labels := make([]prompb.Label, len(ts.Labels))
		for j, lb := range ts.Labels {
			labels[j] = prompb.Label{
				Name:  lb.Name,
				Value: lb.Value,
			}
		}
		pbTs := prompb.TimeSeries{
			Labels: labels,
			Samples: []prompb.Sample{{
				// Timestamp for remote write should be in milliseconds.
				Timestamp: ts.Sample.Time.UnixNano() / int64(time.Millisecond),
				Value:     ts.Sample.Value,
			}},
		}
		res[i] = pbTs
	}
	return res
}

// WriteError returned if HTTP call is finished with response status code, but it was not successful.
type WriteError struct {
	err  error
	code int
}

func (e *WriteError) Error() string {
	return e.err.Error()
}

func (e *WriteError) StatusCode() int {
	return e.code
}
