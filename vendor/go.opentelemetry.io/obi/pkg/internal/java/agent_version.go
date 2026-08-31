// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	// agentVersionProperty is the JVM system property the OBI Java agent publishes when it
	// loads, so that OBI can tell which agent an already instrumented JVM is running.
	agentVersionProperty = "otel.obi.java.agent.version"

	// agentVersionResource is the agent JAR entry holding agentVersionProperty. The agent reads
	// it at load time and OBI reads it from the JAR it injects, so both sides of the comparison
	// come from the same artifact.
	agentVersionResource = "obi-java-agent-version.properties"
)

var errNoAgentVersion = errors.New("the OBI java agent jar carries no version marker")

// agentVersionFromJar returns the version of the Java agent packaged in jar.
func agentVersionFromJar(jar []byte) (string, error) {
	archive, err := zip.NewReader(bytes.NewReader(jar), int64(len(jar)))
	if err != nil {
		return "", fmt.Errorf("unable to read the embedded OBI java agent: %w", err)
	}

	entry, err := archive.Open(agentVersionResource)
	if err != nil {
		return "", fmt.Errorf("%w: %w", errNoAgentVersion, err)
	}
	defer entry.Close()

	version, err := javaProperty(entry, agentVersionProperty)
	if err != nil {
		return "", fmt.Errorf("unable to read %s: %w", agentVersionResource, err)
	}

	if version == "" {
		return "", errNoAgentVersion
	}

	return version, nil
}

// javaProperty returns the value of key in a java.util.Properties formatted stream, or an empty
// string when the key is absent. It understands the plain "key=value" form only, which is what
// both the agent version resource and the jcmd VM.system_properties output use.
func javaProperty(r io.Reader, key string) (string, error) {
	prefix := key + "="
	reader := bufio.NewReader(r)

	for {
		line, err := reader.ReadString('\n')

		if value, found := strings.CutPrefix(strings.TrimLeft(line, " \t"), prefix); found {
			return strings.TrimSpace(value), nil
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", nil
			}
			return "", err
		}
	}
}
