//go:build integration

package integration

import (
	"testing"
)

func testREDMetricsPythonHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:8081",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForNodeHTTPLibrary(t, testCaseURL, "python3.11") // reusing what we do for NodeJS
		})
	}
}

func testREDMetricsPythonHTTPS(t *testing.T) {
	for _, testCaseURL := range []string{
		"https://localhost:8081",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForNodeHTTPLibrary(t, testCaseURL, "python3.11") // reusing what we do for NodeJS
		})
	}
}
