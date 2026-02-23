// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package promtest provides some convenience functions for prometheus handling in integration tests.
package promtest // import "go.opentelemetry.io/obi/internal/test/integration/components/promtest"

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
	Value  []any
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

type ScrapedMetric struct {
	Name   string
	Value  float64
	Labels map[string]string
}

// Scrape implements a simple, synchronous, validation-oriented (non-error-prone)
// scrape of Prometheus metrics towards a /metrics HTTP endpoint
func Scrape(metricsURL string) ([]ScrapedMetric, error) {
	resp, err := http.Get(metricsURL)
	if err != nil {
		return nil, fmt.Errorf("scraping %s: %w", metricsURL, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned %s", metricsURL, resp.Status)
	}
	var metrics []ScrapedMetric
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}
		metrics = append(metrics, parseMetric(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading response of %s: %w", metricsURL, err)
	}
	return metrics, nil
}

// parse metric assumes no escaped values for ",{} inside the label values
func parseMetric(text string) ScrapedMetric {
	split := strings.Split(text, "{")
	name := split[0]
	split = strings.Split(split[1], "} ")
	labelsStr, valueStr := split[0], split[1]
	value, _ := strconv.ParseFloat(valueStr, 64)
	labels := map[string]string{}
	for keyValStr := range strings.SplitSeq(labelsStr, ",") {
		split := strings.Split(keyValStr, "=")
		labels[split[0]] = strings.Trim(split[1], `"`)
	}
	return ScrapedMetric{
		Name:   name,
		Value:  value,
		Labels: labels,
	}
}
