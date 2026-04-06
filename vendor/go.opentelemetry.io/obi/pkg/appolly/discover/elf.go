// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/export/attributes"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
)

const (
	envServiceName      = "OTEL_SERVICE_NAME"
	envResourceAttrs    = "OTEL_RESOURCE_ATTRIBUTES"
	serviceNameKey      = "service.name"
	serviceNamespaceKey = "service.namespace"
)

func setServiceEnvVariables(service svc.Attrs, envVars map[string]string) svc.Attrs {
	service.EnvVars = envVars
	m := map[attr.Name]string{}
	allVars := map[string]string{}

	// We pull out the metadata from the OTEL resource variables. This is better than taking them from
	// Kubernetes, because the variables will be fully resolved when they are passed to the process.

	// Parse all resource attributes provided to the process and add them to the metadata
	if resourceAttrs, ok := service.EnvVars[envResourceAttrs]; ok {
		collect := func(k string, v string) {
			allVars[k] = v
		}
		attributes.ParseOTELResourceVariable(resourceAttrs, collect)

		for k, v := range allVars {
			// ignore empty or unresolved variables
			if v != "" && !strings.HasPrefix(v, "$") {
				m[attr.Name(k)] = v
			}
		}
	}

	// thread safe map update
	service.Metadata = m

	// Set the service name and namespace, if we found non-empty, resolved names, in the OTEL variables.
	// 1. For service name, first consider OTEL_SERVICE_NAME, then look for service.name in OTEL_RESOURCE_ATTRIBUTES
	// 2. For service namespace, look in OTEL_RESOURCE_ATTRIBUTES
	if svcName := service.EnvVars[envServiceName]; svcName != "" && !strings.HasPrefix(svcName, "$") {
		service.UID.Name = svcName
	} else if svcName := allVars[serviceNameKey]; svcName != "" && !strings.HasPrefix(svcName, "$") {
		service.UID.Name = svcName
	}

	if svcNamespace := allVars[serviceNamespaceKey]; svcNamespace != "" && !strings.HasPrefix(svcNamespace, "$") {
		service.UID.Namespace = svcNamespace
	}

	return service
}
