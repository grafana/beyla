//go:build integration

package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/grafana/beyla/v3/internal/test/tools/docker"
	"github.com/grafana/beyla/v3/internal/test/tools/promtest"
)

const (
	webhookMutateURL = "https://localhost:9443/mutate"
	webhookHealthURL = "https://localhost:9443/health"
)

var insecureClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	},
}

func TestWebhookMetrics(t *testing.T) {
	t.Skip("TODO: This should be tested in K8s with the K8s-injector. This test won't work because an _owner_ is mandatory")
	certsDir := path.Join(pathRoot, "internal/test/integration/testdata/certs")
	require.NoError(t, generateTestCerts(certsDir))

	compose, err := docker.ComposeSuite(
		"compose/docker-compose-webhook.yml",
		path.Join(pathOutput, "test-suite-webhook-metrics.log"),
	)
	require.NoError(t, err)
	require.NoError(t, compose.Up())
	defer func() { require.NoError(t, compose.Close()) }()

	waitForWebhookReady(t)

	pq := promtest.Client{HostPort: prometheusHostPort}

	t.Run("matched_pod_emits_success", func(t *testing.T) {
		sendAdmissionReview(t, makeAdmissionReview("test-ns", "my-app", nil, nil))

		require.EventuallyWithT(t, func(t *assert.CollectT) {
			results, err := pq.Query(`beyla_sdk_injection_requests_total{outcome="success"}`)
			require.NoError(t, err)
			require.NotEmpty(t, results)
		}, testTimeout, 100*time.Millisecond)
	})

	t.Run("unmatched_namespace_emits_no_matching_selector", func(t *testing.T) {
		sendAdmissionReview(t, makeAdmissionReview("other-ns", "my-app", nil, nil))

		require.EventuallyWithT(t, func(t *assert.CollectT) {
			results, err := pq.Query(`beyla_sdk_injection_requests_total{outcome="no_matching_selector"}`)
			require.NoError(t, err)
			require.NotEmpty(t, results)
		}, testTimeout, 100*time.Millisecond)
	})

	t.Run("already_instrumented_pod_emits_already_instrumented", func(t *testing.T) {
		labels := map[string]string{"com.grafana.beyla/instrumented": "v0.1.0"}
		sendAdmissionReview(t, makeAdmissionReview("test-ns", "instrumented-app", labels, nil))

		require.EventuallyWithT(t, func(t *assert.CollectT) {
			results, err := pq.Query(`beyla_sdk_injection_requests_total{outcome="already_instrumented"}`)
			require.NoError(t, err)
			require.NotEmpty(t, results)
		}, testTimeout, 100*time.Millisecond)
	})
}

// generateTestCerts writes a fresh self-signed cert and key to dir, creating the directory if needed.
func generateTestCerts(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certFile, err := os.Create(path.Join(dir, "tls.crt"))
	if err != nil {
		return err
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyFile, err := os.Create(path.Join(dir, "tls.key"))
	if err != nil {
		return err
	}
	defer keyFile.Close()
	return pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// waitForWebhookReady polls the webhook health endpoint until it responds.
func waitForWebhookReady(t *testing.T) {
	t.Helper()
	require.EventuallyWithT(t, func(t *assert.CollectT) {
		resp, err := insecureClient.Get(webhookHealthURL)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}, testTimeout, 100*time.Millisecond)
}

// makeAdmissionReview builds a minimal AdmissionReview for a pod in the given namespace.
func makeAdmissionReview(ns, name string, labels map[string]string, env []corev1.EnvVar) *admissionv1.AdmissionReview {
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels:    labels,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "app", Image: "nginx:latest", Env: env},
			},
		},
	}
	raw, _ := json.Marshal(pod)
	return &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID: "test-uid",
			Kind: metav1.GroupVersionKind{
				Group:   "",
				Version: "v1",
				Kind:    "Pod",
			},
			Namespace: ns,
			Object:    runtime.RawExtension{Raw: raw},
		},
	}
}

// sendAdmissionReview POSTs an AdmissionReview to the webhook mutate endpoint.
func sendAdmissionReview(t *testing.T, ar *admissionv1.AdmissionReview) {
	t.Helper()
	body, err := json.Marshal(ar)
	require.NoError(t, err)

	resp, err := insecureClient.Post(webhookMutateURL, "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
