// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package convert // import "go.opentelemetry.io/obi/internal/config/convert"

import (
	"go.opentelemetry.io/obi/internal/config/schema"
	"go.opentelemetry.io/obi/pkg/kube/kubeflags"
)

func v2KubernetesMode(mode kubeflags.EnableFlag) schema.KubernetesMode {
	switch mode {
	case kubeflags.EnabledTrue:
		return schema.KubernetesModeEnabled
	case kubeflags.EnabledFalse:
		return schema.KubernetesModeDisabled
	case kubeflags.EnabledAutodetect, "":
		return schema.KubernetesModeAutodetect
	default:
		return schema.KubernetesMode(mode)
	}
}

func runtimeKubernetesMode(mode schema.KubernetesMode) kubeflags.EnableFlag {
	switch mode {
	case schema.KubernetesModeEnabled:
		return kubeflags.EnabledTrue
	case schema.KubernetesModeDisabled:
		return kubeflags.EnabledFalse
	case schema.KubernetesModeAutodetect:
		return kubeflags.EnabledAutodetect
	default:
		return kubeflags.EnableFlag(mode)
	}
}
