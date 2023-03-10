// Package prom provides some convenience functions for prometheus handling in integration tests
package prom

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"golang.org/x/exp/slog"
)

var log = slog.With("component", "prom.Client")

type queryResult struct {
	Status string `json:"status"`
	Data   data   `json:"data"`
}

type data struct {
	Result     []Result `json:"result"`
	ResultType string   `json:"resultType"`
}

// Result structure assumes that resultType is always == "vector"
type Result struct {
	Metric map[string]string `json:"metric"`
	Value  []interface{}
}

type Client struct {
	HostPort string
}

func (c *Client) Query(promQL string) ([]Result, error) {
	qurl := "http://" + c.HostPort + "/api/v1/query?query=" + url.PathEscape(promQL)
	log.Debug("querying prometheus", "query", promQL, "url", qurl)
	resp, err := http.Get(qurl)
	if err != nil {
		return nil, fmt.Errorf("querying prometheus: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("can't read response body: %w", err)
	}
	log.Debug(string(body))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("prometheus returned status %q", resp.Status)
	}
	qr := queryResult{}
	if err := json.Unmarshal(body, &qr); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}
	slog.Debug("prometheus query successful",
		"status", qr.Status,
		"resultType", qr.Data.ResultType)
	return qr.Data.Result, nil
}
