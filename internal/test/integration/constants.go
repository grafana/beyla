//go:build integration

package integration

import "time"

const (
	instrumentedServiceStdURL         = "http://localhost:8080"
	instrumentedServiceGinURL         = "http://localhost:8081"
	instrumentedServiceGorillaURL     = "http://localhost:8082"
	instrumentedServiceGorillaMidURL  = "http://localhost:8083"
	instrumentedServiceGorillaMid2URL = "http://localhost:8087"
	instrumentedServiceStdTLSURL      = "https://localhost:8383"
	instrumentedServiceJSONRPCURL     = "http://localhost:8088"
	prometheusHostPort                = "localhost:9090"
	jaegerQueryURL                    = "http://localhost:16686/api/traces"

	testTimeout = 60 * time.Second
)
