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

package netdb

import (
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
)

func log() *slog.Logger {
	return slog.With("component", "netdb.ServiceNames")
}

type numKey struct {
	port           int
	protocolNumber int
}

type nameKey struct {
	port         int
	protocolName string
}

type ServiceNames struct {
	protoNums map[int]struct{}
	// key: protocol name, value: protocol number
	protoNames  map[string]int
	byPort      map[int]string
	byProtoNum  map[numKey]string
	byProtoName map[nameKey]string
}

// LoadServicesDB receives readers to the /etc/protocols and /etc/services formatted content
// and returns a database that allow querying service names from ports and protocol information
func LoadServicesDB(protocols, services io.Reader) (*ServiceNames, error) {
	log := log().With("method", "LoadServicesDB")
	db := ServiceNames{
		protoNums:   map[int]struct{}{},
		protoNames:  map[string]int{},
		byPort:      map[int]string{},
		byProtoNum:  map[numKey]string{},
		byProtoName: map[nameKey]string{},
	}
	// Load protocols
	protoData, err := io.ReadAll(protocols)
	if err != nil {
		return nil, fmt.Errorf("reading protocols data: %w", err)
	}

	// key: proto name, value: aliases
	protoAliases := map[string][]string{}

	for i, line := range strings.Split(string(protoData), "\n") {
		line = strings.TrimSpace(line)
		split := strings.SplitN(line, "#", 2)
		fields := strings.Fields(split[0])
		if len(fields) < 2 {
			continue
		}

		num, err := strconv.ParseInt(fields[1], 10, 32)
		if err != nil {
			log.Debug("wrong protocol number. Ignoring entry",
				"error", err,
				"lineNum", i,
				"line", line,
			)
			continue
		}

		db.protoNums[int(num)] = struct{}{}
		db.protoNames[fields[0]] = int(num)
		for _, alias := range fields[2:] {
			db.protoNames[alias] = int(num)
		}
		protoAliases[fields[0]] = fields[2:]
	}

	// Load services
	svcData, err := io.ReadAll(services)
	if err != nil {
		return nil, fmt.Errorf("reading services data: %w", err)
	}

	for i, line := range strings.Split(string(svcData), "\n") {
		line = strings.TrimSpace(line)
		split := strings.SplitN(line, "#", 2)
		fields := strings.Fields(split[0])
		if len(fields) < 2 {
			continue
		}

		svcName := fields[0]
		portproto := strings.SplitN(fields[1], "/", 2)
		protoName := portproto[1]
		port, err := strconv.ParseInt(portproto[0], 10, 32)
		if err != nil {
			log.Debug("wrong service port number. Ignoring entry",
				"error", err,
				"lineNum", i,
				"line", line,
			)
			continue
		}
		db.byPort[int(port)] = svcName
		if protoNum, ok := db.protoNames[protoName]; ok {
			db.byProtoNum[numKey{port: int(port), protocolNumber: protoNum}] = svcName
		}
		db.byProtoName[nameKey{port: int(port), protocolName: protoName}] = svcName
		for _, alias := range protoAliases[protoName] {
			db.byProtoName[nameKey{port: int(port), protocolName: alias}] = svcName
		}
	}
	return &db, nil
}

// ByPortAndProtocolName returns the service name given a port and a protocol name (or
// its alias). If the protocol does not exist, returns the name of any service matching
// the port number.
func (db *ServiceNames) ByPortAndProtocolName(port int, nameOrAlias string) string {
	if _, ok := db.protoNames[nameOrAlias]; ok {
		return db.byProtoName[nameKey{port: port, protocolName: nameOrAlias}]
	}
	return db.byPort[port]
}

// ByPortAndProtocolNumber returns the service name given a port and a protocol number.
// If the protocol does not exist, returns the name of any service matching
// the port number.
func (db *ServiceNames) ByPortAndProtocolNumber(port, protoNum int) string {
	if _, ok := db.protoNums[protoNum]; ok {
		return db.byProtoNum[numKey{port: port, protocolNumber: protoNum}]
	}
	return db.byPort[port]
}
