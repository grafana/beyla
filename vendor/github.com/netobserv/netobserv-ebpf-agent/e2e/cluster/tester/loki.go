package tester

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/sirupsen/logrus"
)

const (
	pathReady      = "/ready"
	pathQueryRange = "/loki/api/v1/query_range"
	queryArgLimit  = "limit"
	queryArgQuery  = "query"
	queryStep      = "step=30m"
)

var llog = logrus.WithField("component", "loki.Tester")

// Loki enables basic testing operations for the Loki component of the test cluster
type Loki struct {
	BaseURL string
}

func (l *Loki) get(pathQuery string) (status int, body string, err error) {
	client := http.Client{}
	reqURL := l.BaseURL + pathQuery
	llog.WithField("url", reqURL).Debug("HTTP GET request")
	resp, err := client.Get(reqURL)
	if err != nil {
		return 0, "", err
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(bodyBytes), nil
}

// Ready returns error if the Loki API is ready to accept calls
func (l *Loki) Ready() error {
	status, body, err := l.get(pathReady)
	if err != nil {
		return fmt.Errorf("loki is not ready: %w", err)
	} else if status != http.StatusOK {
		return fmt.Errorf("loki is not ready (status %d): %s", status, body)
	}
	return nil
}

// Query executes an arbitrary logQL query, given a limit in the results
func (l *Loki) Query(limit int, logQL string) (*LokiQueryResponse, error) {
	status, body, err := l.get(fmt.Sprintf("%s?%s=%d&%s&%s=%s",
		pathQueryRange, queryArgLimit, limit, queryStep,
		queryArgQuery, url.QueryEscape(logQL)))
	if err != nil {
		return nil, fmt.Errorf("loki request error: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", status, body)
	}
	response := LokiQueryResponse{}
	if err := json.Unmarshal([]byte(body), &response); err != nil {
		llog.WithError(err).Debug(body)
		return nil, fmt.Errorf("can't unmarshal response body: %w", err)
	}
	return &response, nil
}

type LokiQueryResponse struct {
	Status string        `json:"status"`
	Data   LokiQueryData `json:"data"`
}

type LokiQueryData struct {
	Result []LokiQueryResult `json:"result"`
}

type LokiQueryResult struct {
	Stream map[string]string `json:"stream"`
	Values []FlowValue       `json:"values"`
}

type FlowValue []string

func (f FlowValue) FlowData() (map[string]interface{}, error) {
	if len(f) < 2 {
		return nil, fmt.Errorf("incorrect flow data: %v", f)
	}
	flow := map[string]interface{}{}
	if err := json.Unmarshal([]byte(f[1]), &flow); err != nil {
		return nil, fmt.Errorf("can't unmarshall JSON flow: %w", err)
	}
	return flow, nil
}
