// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kubecache // import "go.opentelemetry.io/obi/pkg/kube/kubecache"

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// TLSConfig turns on TLS when CertFile and KeyFile are set, and mutual TLS when ClientCAFile is set too.
type TLSConfig struct {
	// CertFile and KeyFile are the PEM-encoded certificate and private key of the service
	CertFile string `yaml:"cert_file" env:"CERT_FILE"`
	KeyFile  string `yaml:"key_file" env:"KEY_FILE"`
	// ClientCAFile makes the service require client certificates signed by this CA
	ClientCAFile string `yaml:"client_ca_file" env:"CLIENT_CA_FILE"`
}

func (c TLSConfig) Validate() error {
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("tls.cert_file and tls.key_file must be set together")
	}
	if c.ClientCAFile != "" && c.CertFile == "" {
		return errors.New("tls.client_ca_file requires tls.cert_file and tls.key_file")
	}
	return nil
}

// Credentials returns the gRPC transport credentials for the cache service.
func (c TLSConfig) Credentials() (credentials.TransportCredentials, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.CertFile == "" {
		return insecure.NewCredentials(), nil
	}
	certificate, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading cache service certificate: %w", err)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	if c.ClientCAFile != "" {
		if cfg.ClientCAs, err = loadCertPool(c.ClientCAFile); err != nil {
			return nil, err
		}
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return credentials.NewTLS(cfg), nil
}

// ClientTLSConfig makes OBI use TLS for the cache service when CAFile or a client certificate is set.
type ClientTLSConfig struct {
	// CAFile verifies the cache service certificate
	CAFile string
	// CertFile and KeyFile are the client certificate for a cache service that requires one
	CertFile string
	KeyFile  string
	// ServerName overrides the host from the cache address when checking its certificate
	ServerName string
}

func (c ClientTLSConfig) enabled() bool {
	return c.CAFile != "" || c.CertFile != "" || c.KeyFile != ""
}

func (c ClientTLSConfig) Validate() error {
	if (c.CertFile == "") != (c.KeyFile == "") {
		return errors.New("kubernetes metadata_cache tls cert_file and key_file must be set together")
	}
	if c.ServerName != "" && !c.enabled() {
		return errors.New("kubernetes metadata_cache tls server_name requires ca_file or a client certificate")
	}
	return nil
}

// Credentials returns the gRPC transport credentials for connecting to the cache service.
func (c ClientTLSConfig) Credentials() (credentials.TransportCredentials, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.enabled() {
		return insecure.NewCredentials(), nil
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.ServerName}
	if c.CAFile != "" {
		pool, err := loadCertPool(c.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	if c.CertFile != "" {
		certificate, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("loading cache client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{certificate}
	}
	return credentials.NewTLS(cfg), nil
}

func loadCertPool(file string) (*x509.CertPool, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("loading CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA file %s contains no certificates", file)
	}
	return pool, nil
}
