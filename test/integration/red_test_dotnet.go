//go:build integration

package integration

import (
	"testing"
)

func testREDMetricsDotNetHTTP(t *testing.T) {
	for _, testCaseURL := range []string{
		"http://localhost:5267",
	} {
		t.Run(testCaseURL, func(t *testing.T) {
			waitForTestComponents(t, testCaseURL)
			testREDMetricsForNodeHTTPLibrary(t, testCaseURL, "dotnetserver") // reusing what we do for NodeJS
		})
	}
}
