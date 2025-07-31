// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package meta

import (
	"context"
	"errors"
	"fmt"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
)

func splitMaybeSubscriptedPath(fieldPath string) (string, string, bool) {
	if !strings.HasSuffix(fieldPath, "']") {
		return fieldPath, "", false
	}
	s := strings.TrimSuffix(fieldPath, "']")
	parts := strings.SplitN(s, "['", 2)
	if len(parts) < 2 {
		return fieldPath, "", false
	}
	if len(parts[0]) == 0 {
		return fieldPath, "", false
	}
	return parts[0], parts[1], true
}

// formatMap formats map[string]string to a string.
func formatMap(m map[string]string) (fmtStr string) {
	// output with keys in sorted order to provide stable output
	keys := sets.NewString()
	for key := range m {
		keys.Insert(key)
	}
	for _, key := range keys.List() {
		fmtStr += fmt.Sprintf("%v=%q\n", key, m[key])
	}
	fmtStr = strings.TrimSuffix(fmtStr, "\n")

	return
}

func extractFieldPathAsString(accessor metav1.ObjectMeta, fieldPath string) (string, error) {
	if path, subscript, ok := splitMaybeSubscriptedPath(fieldPath); ok {
		switch path {
		case "metadata.annotations":
			if errs := validation.IsQualifiedName(strings.ToLower(subscript)); len(errs) != 0 {
				return "", fmt.Errorf("invalid key subscript in %s: %s", fieldPath, strings.Join(errs, ";"))
			}
			return accessor.GetAnnotations()[subscript], nil
		case "metadata.labels":
			if errs := validation.IsQualifiedName(subscript); len(errs) != 0 {
				return "", fmt.Errorf("invalid key subscript in %s: %s", fieldPath, strings.Join(errs, ";"))
			}
			return accessor.GetLabels()[subscript], nil
		default:
			return "", fmt.Errorf("fieldPath %q does not support subscript", fieldPath)
		}
	}

	switch fieldPath {
	case "metadata.annotations":
		return formatMap(accessor.GetAnnotations()), nil
	case "metadata.labels":
		return formatMap(accessor.GetLabels()), nil
	case "metadata.name":
		return accessor.GetName(), nil
	case "metadata.namespace":
		return accessor.GetNamespace(), nil
	case "metadata.uid":
		return string(accessor.GetUID()), nil
	}

	return "", fmt.Errorf("unsupported fieldPath: %v", fieldPath)
}

func getFieldRef(accessor metav1.ObjectMeta, from *v1.EnvVarSource) (string, error) {
	return extractFieldPathAsString(accessor, from.FieldRef.FieldPath)
}

func extractConfigMapRefValue(configMap *v1.ConfigMap, err error, configMapSelector *v1.ConfigMapKeySelector) (string, error) {
	if err != nil {
		return "", err
	}
	if data, ok := configMap.Data[configMapSelector.Key]; ok {
		return data, nil
	}
	return "", fmt.Errorf("key %s not found in config map %s", configMapSelector.Key, configMapSelector.Name)
}

func getConfigMapRefValue(client kubernetes.Interface, namespace string, configMapSelector *v1.ConfigMapKeySelector) (string, error) {
	configMap, err := client.CoreV1().ConfigMaps(namespace).Get(context.TODO(), configMapSelector.Name, metav1.GetOptions{})
	return extractConfigMapRefValue(configMap, err, configMapSelector)
}

func extractSecretRefValue(secret *v1.Secret, err error, secretSelector *v1.SecretKeySelector) (string, error) {
	if err != nil {
		return "", err
	}
	if data, ok := secret.Data[secretSelector.Key]; ok {
		return string(data), nil
	}
	return "", fmt.Errorf("key %s not found in secret %s", secretSelector.Key, secretSelector.Name)
}

func getSecretRefValue(client kubernetes.Interface, namespace string, secretSelector *v1.SecretKeySelector) (string, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(context.TODO(), secretSelector.Name, metav1.GetOptions{})
	return extractSecretRefValue(secret, err, secretSelector)
}

// GetEnvVarRefValue code adopted from https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/set/env/env_resolve.go#L248
func GetEnvVarRefValue(kc kubernetes.Interface, ns string, from *v1.EnvVarSource, obj metav1.ObjectMeta) (string, error) {
	if from.SecretKeyRef != nil {
		return getSecretRefValue(kc, ns, from.SecretKeyRef)
	}

	if from.ConfigMapKeyRef != nil {
		return getConfigMapRefValue(kc, ns, from.ConfigMapKeyRef)
	}

	if from.FieldRef != nil {
		return getFieldRef(obj, from)
	}

	return "", errors.New("invalid valueFrom")
}
