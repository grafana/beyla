// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel // import "go.opentelemetry.io/obi/pkg/export/otel"

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

func otlpTLSConfig(signal string, skipVerify bool) (*tls.Config, error) {
	prefix := "OTEL_EXPORTER_OTLP_" + signal
	certFile := os.Getenv(prefix + "_CERTIFICATE")
	if certFile == "" {
		certFile = os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE")
	}
	clientCertFile := os.Getenv(prefix + "_CLIENT_CERTIFICATE")
	clientKeyFile := os.Getenv(prefix + "_CLIENT_KEY")
	if clientCertFile == "" || clientKeyFile == "" {
		clientCertFile = os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE")
		clientKeyFile = os.Getenv("OTEL_EXPORTER_OTLP_CLIENT_KEY")
	}
	if certFile == "" && clientCertFile == "" && !skipVerify {
		return nil, nil
	}
	config := &tls.Config{InsecureSkipVerify: skipVerify}
	if certFile != "" {
		data, err := os.ReadFile(certFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("no certificates found in %s", certFile)
		}
		config.RootCAs = pool
	}
	if clientCertFile != "" && clientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
	}
	return config, nil
}
