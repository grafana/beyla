// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package agent

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
)

func buildTLSConfig(cfg *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.KafkaTLSInsecureSkipVerify,
	}
	if cfg.KafkaTLSCACertPath != "" {
		caCert, err := ioutil.ReadFile(cfg.KafkaTLSCACertPath)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = x509.NewCertPool()
		tlsConfig.RootCAs.AppendCertsFromPEM(caCert)

		if cfg.KafkaTLSUserCertPath != "" && cfg.KafkaTLSUserKeyPath != "" {
			userCert, err := ioutil.ReadFile(cfg.KafkaTLSUserCertPath)
			if err != nil {
				return nil, err
			}
			userKey, err := ioutil.ReadFile(cfg.KafkaTLSUserKeyPath)
			if err != nil {
				return nil, err
			}
			pair, err := tls.X509KeyPair([]byte(userCert), []byte(userKey))
			if err != nil {
				return nil, err
			}
			tlsConfig.Certificates = []tls.Certificate{pair}
		}
		return tlsConfig, nil
	}
	return nil, nil
}
