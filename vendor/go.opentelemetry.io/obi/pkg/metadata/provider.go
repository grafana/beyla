// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metadata // import "go.opentelemetry.io/obi/pkg/metadata"

import "go.opentelemetry.io/obi/pkg/kube"

type MetadataProvider struct {
	K8sInformer   *kube.MetadataProvider
	CloudMetadata CloudMetadataConfig
}
