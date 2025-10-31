// Package kube contains some tools to setup and use a Kind cluster
package kube

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/vladimirvivien/gexe"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/yaml"
	yamlutil "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/e2e-framework/pkg/env"
	"sigs.k8s.io/e2e-framework/pkg/envconf"
	"sigs.k8s.io/e2e-framework/pkg/envfuncs"
	"sigs.k8s.io/e2e-framework/support/kind"

	"github.com/grafana/beyla/v2/internal/test/integration/components/jaeger"
	"github.com/grafana/beyla/v2/internal/test/integration/components/prom"
	"github.com/grafana/beyla/v2/internal/test/integration/k8s/common/testpath"
)

const (
	kindImage = "kindest/node:v1.27.3"

	destroyPodsWithLabel = "teardown=delete"
)

func log() *slog.Logger {
	return slog.With("component", "kube.Kind")
}

// Kind cluster deployed by each TestMain function, prepared to run a given test scenario.
type Kind struct {
	kindConfigPath  string
	clusterName     string
	testEnv         env.Environment
	timeout         time.Duration
	deployManifests []string
	localImages     []string
	logsDir         string
	promEndpoint    string
	jaegerEndpoint  string
}

// Option that can be passed to the NewKind function in order to change the configuration
// of the test cluster
type Option func(k *Kind)

// Deploy can be passed to NewKind to deploy extra components, in addition to the base deployment.
func Deploy(manifest string) Option {
	return func(k *Kind) {
		k.deployManifests = append(k.deployManifests, manifest)
	}
}

// KindConfig can be passed to NewKind to override the default Kind cluster configuration.
func KindConfig(filePath string) Option {
	return func(k *Kind) {
		k.kindConfigPath = filePath
	}
}

// ExportLogs can be passed to NewKind to specify the folder where the kubernetes logs will be exported after the tests.
// Default: k8s.KindLogs
func ExportLogs(folder string) Option {
	return func(k *Kind) {
		k.logsDir = folder
	}
}

// ExportPrometheus overrides the prometheus host:port, where all the stored metrics will be collected from
// before the Kind cluster is shut down. Default: localhost:39090
func ExportPrometheus(hostPort string) Option {
	return func(k *Kind) {
		k.promEndpoint = hostPort
	}
}

// ExportJaeger overrides a jaeger host:port, where all the stored traces will be collected from
// before the Kind cluster is shut down. Default: localhost:36686
func ExportJaeger(hostPort string) Option {
	return func(k *Kind) {
		k.jaegerEndpoint = hostPort
	}
}

// Timeout for long-running operations (e.g. deployments, readiness probes...)
func Timeout(t time.Duration) Option {
	return func(k *Kind) {
		k.timeout = t
	}
}

// LocalImage is passed to NewKind to allow loading a local Docker image into the cluster
func LocalImage(nameTag string) Option {
	return func(k *Kind) {
		k.localImages = append(k.localImages, nameTag)
	}
}

// NewKind creates a kind cluster given a name and set of Option instances.
func NewKind(kindClusterName string, options ...Option) *Kind {
	k := &Kind{
		testEnv:        env.New(),
		clusterName:    kindClusterName,
		timeout:        2 * time.Minute,
		promEndpoint:   "localhost:39090",
		jaegerEndpoint: "localhost:36686",
		logsDir:        testpath.KindLogs,
	}
	for _, option := range options {
		option(k)
	}
	return k
}

// Run the Kind cluster for the later execution of tests.
func (k *Kind) Run(m *testing.M) {
	log := log()
	var funcs []env.Func
	if k.kindConfigPath != "" {
		log.Info("adding func: createKindCluster", "name", k.clusterName, "image", kindImage, "path", k.kindConfigPath)
		funcs = append(funcs,
			// TODO: allow overriding kindImage
			envfuncs.CreateClusterWithConfig(kind.NewProvider(), k.clusterName, k.kindConfigPath, kind.WithImage(kindImage)))
	} else {
		log.Info("adding func: createKindCluster", "name", k.clusterName)
		funcs = append(funcs,
			envfuncs.CreateCluster(kind.NewProvider(), k.clusterName))
	}
	for _, img := range k.localImages {
		log.Info("adding func: loadLocalImage", "img", img)
		funcs = append(funcs, k.loadLocalImage(img))
	}
	for _, mf := range k.deployManifests {
		log.Info("adding func: deployManifests", "manifest", mf)
		funcs = append(funcs, deploy(mf))
	}

	log.Info("starting kind setup")
	code := k.testEnv.Setup(funcs...).
		Finish(
			k.exportLogs(),
			k.exportAllMetrics(),
			k.exportAllTraces(),
			k.deleteLabeled(),
			envfuncs.DestroyCluster(k.clusterName),
			k.cleanupDocker(),
		).Run(m)
	log.With("returnCode", code).Info("tests finished run")
}

// cleanupDocker prunes docker resources after the cluster is destroyed to save disk space
func (k *Kind) cleanupDocker() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		log := log()
		log.Info("cleaning up docker resources to save disk space")
		exe := gexe.New()
		out := exe.Run("docker system prune -af --volumes")
		log.With("out", out).Info("docker cleanup completed")
		return ctx, nil
	}
}

// export logs into the e2e-logs folder of the base directory.
func (k *Kind) exportLogs() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		if k.logsDir == "" {
			return ctx, nil
		}
		log := log()
		log.With("directory", k.logsDir).Info("exporting cluster logs")
		exe := gexe.New()
		out := exe.Run("kind export logs " + k.logsDir + " --name " + k.clusterName)
		log.With("out", out).Info("exported cluster logs")
		return ctx, nil
	}
}

func (k *Kind) exportAllMetrics() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		if k.promEndpoint == "" {
			return ctx, nil
		}
		_ = os.MkdirAll(path.Join(k.logsDir, k.clusterName), 0755)
		out, err := os.Create(path.Join(k.logsDir, k.clusterName, "prometheus_metrics.txt"))
		if err != nil {
			log().Error("creating prometheus export file", "error", err)
			return ctx, nil
		}
		defer out.Close()
		if err := DumpMetrics(out, k.promEndpoint); err != nil {
			log().Error("dumping prometheus metrics", "error", err)
			return ctx, nil
		}
		return ctx, nil
	}
}

func (k *Kind) exportAllTraces() env.Func {
	return func(ctx context.Context, _ *envconf.Config) (context.Context, error) {
		if k.promEndpoint == "" {
			return ctx, nil
		}
		_ = os.MkdirAll(path.Join(k.logsDir, k.clusterName), 0755)
		out, err := os.Create(path.Join(k.logsDir, k.clusterName, "jaeger_traces.txt"))
		if err != nil {
			log().Error("creating jaeger export file", "error", err)
			return ctx, nil
		}
		defer out.Close()
		if err := DumpTraces(out, k.jaegerEndpoint); err != nil {
			log().Error("dumping jaeger traces", "error", err)
			return ctx, nil
		}
		return ctx, nil
	}
}

// deleteLabeled sends a kill signal to all the Beyla instances before tearing down the
// kind cluster, in order to force them to write the coverage information
// This method assumes that all the beyla pod instances are labeled as "teardown=delete"
func (k *Kind) deleteLabeled() env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		kclient, err := kubernetes.NewForConfig(config.Client().RESTConfig())
		if err != nil {
			return ctx, fmt.Errorf("creating kubernetes client for deletion: %w", err)
		}
		log := log().With("method", "deleteLabeled")
		log.Info("searching for pods to delete before tearing down Kind")
		podsClient := kclient.CoreV1().Pods("")
		pods, err := podsClient.List(ctx, metav1.ListOptions{
			LabelSelector: destroyPodsWithLabel,
		})
		if err != nil {
			log.Error("can't list pods", "error", err)
			return ctx, err
		}
		for i := range pods.Items {
			pod := &pods.Items[i]
			plog := log.With("podName", pod.Name, "namespace", pod.Namespace)
			plog.Info("deleting")
			pc := kclient.CoreV1().Pods(pod.Namespace)
			if err := pc.Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
				plog.Error("can't delete pod", "error", err)
				continue
			}
			// wait for the pod to be stopped
			for p, err := pc.Get(ctx, pod.Name, metav1.GetOptions{}); err == nil && p != nil; {
				plog.Info("waiting 1s for pod to be stopped", "status", string(p.Status.Phase))
				time.Sleep(time.Second)
				p, err = pc.Get(ctx, pod.Name, metav1.GetOptions{})
			}
		}
		return ctx, nil
	}
}

// TestEnv returns the env.Environment object, useful for unit tests that need to interact with the Kubernetes API.
func (k *Kind) TestEnv() env.Environment {
	return k.testEnv
}

func deploy(manifest string) env.Func {
	return func(ctx context.Context, cfg *envconf.Config) (context.Context, error) {
		if err := deployManifestFile(manifest, cfg); err != nil {
			return ctx, fmt.Errorf("deploying manifest file: %w", err)
		}
		return ctx, nil
	}
}

// deployManifestFile deploys a yaml manifest file
// credits to https://gist.github.com/pytimer/0ad436972a073bb37b8b6b8b474520fc
func deployManifestFile(
	manifestFile string,
	cfg *envconf.Config,
) error {
	log := log()
	log.With("file", manifestFile).Info("deploying manifest file")

	b, err := os.ReadFile(manifestFile)
	if err != nil {
		return fmt.Errorf("reading manifest file %q: %w", manifestFile, err)
	}

	return deployManifest(cfg, string(b))
}

func deployManifest(cfg *envconf.Config, manifest string) error {
	return applyManifest(cfg, manifest, func(dri dynamic.ResourceInterface, obj *unstructured.Unstructured) error {
		if _, err := dri.Create(context.Background(), obj, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("deploying manifest: %w", err)
		}
		return nil
	})
}

func deleteManifestFile(
	manifestFile string,
	cfg *envconf.Config,
) error {
	log := log()
	log.With("file", manifestFile).Info("deleting manifest file")

	b, err := os.ReadFile(manifestFile)
	if err != nil {
		return fmt.Errorf("reading manifest file %q: %w", manifestFile, err)
	}

	return deleteManifest(cfg, string(b))
}

func DeleteExistingManifestFile(cfg *envconf.Config, manifest string) error {
	return deleteManifestFile(manifest, cfg)
}

func DeployManifestFile(cfg *envconf.Config, manifest string) error {
	return deployManifestFile(manifest, cfg)
}

func deleteManifest(cfg *envconf.Config, manifest string) error {
	return applyManifest(cfg, manifest, func(dri dynamic.ResourceInterface, obj *unstructured.Unstructured) error {
		if err := dri.Delete(context.Background(), obj.GetName(), metav1.DeleteOptions{}); err != nil {
			return fmt.Errorf("deploying manifest: %w", err)
		}
		return nil
	})
}

func applyManifest(
	cfg *envconf.Config,
	manifest string,
	process func(dri dynamic.ResourceInterface, obj *unstructured.Unstructured) error,
) error {
	decoder := yamlutil.NewYAMLOrJSONDecoder(strings.NewReader(manifest), 100)
	var rawObj runtime.RawExtension
	for {
		if err := decoder.Decode(&rawObj); err != nil {
			if !errors.Is(err, io.EOF) {
				return fmt.Errorf("decoding manifest raw object: %w", err)
			}
			return nil
		}

		if err := decodeAndApply(cfg, rawObj, process); err != nil {
			return fmt.Errorf("decoding and applying manifest: %w", err)
		}
	}
}

func decodeAndApply(
	cfg *envconf.Config,
	rawObj runtime.RawExtension,
	process func(dri dynamic.ResourceInterface, obj *unstructured.Unstructured) error,
) error {
	kclient, err := kubernetes.NewForConfig(cfg.Client().RESTConfig())
	if err != nil {
		return fmt.Errorf("creating kubernetes client: %w", err)
	}
	dd, err := dynamic.NewForConfig(cfg.Client().RESTConfig())
	if err != nil {
		return fmt.Errorf("creating kubernetes dynamic client: %w", err)
	}

	obj, gvk, err := yaml.NewDecodingSerializer(unstructured.UnstructuredJSONScheme).Decode(rawObj.Raw, nil, nil)
	if err != nil {
		return fmt.Errorf("creating yaml decoding serializer: %w", err)
	}
	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return fmt.Errorf("deserializing object in manifest: %w", err)
	}

	unstructuredObj := &unstructured.Unstructured{Object: unstructuredMap}

	gr, err := restmapper.GetAPIGroupResources(kclient.Discovery())
	if err != nil {
		return fmt.Errorf("can't get API group resources: %w", err)
	}

	mapper := restmapper.NewDiscoveryRESTMapper(gr)
	mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return fmt.Errorf("creating REST Mapping: %w", err)
	}

	var dri dynamic.ResourceInterface
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		if unstructuredObj.GetNamespace() == "" {
			unstructuredObj.SetNamespace("default") // TODO: allow overriding default namespace
		}
		dri = dd.Resource(mapping.Resource).Namespace(unstructuredObj.GetNamespace())
	} else {
		dri = dd.Resource(mapping.Resource)
	}

	return process(dri, unstructuredObj)
}

// loadLocalImage loads the agent docker image into the test cluster. It tries both available
// methods, which will selectively work depending on the container backend type
func (k *Kind) loadLocalImage(tag string) env.Func {
	return func(ctx context.Context, config *envconf.Config) (context.Context, error) {
		log().Info("trying to load docker image from local registry", "tag", tag)
		ctx, err := envfuncs.LoadDockerImageToCluster(
			k.clusterName, tag)(ctx, config)
		if err == nil {
			return ctx, nil
		}
		return ctx, fmt.Errorf("couldn't load image %q from local registry: %w", tag, err)
	}
}

func DumpMetrics(out io.Writer, promHostPort string) error {
	if _, err := fmt.Fprintf(out, "===== Dumping metrics from %s ====\n", promHostPort); err != nil {
		return err
	}
	pq := prom.Client{HostPort: promHostPort}
	results, err := pq.Query(`{__name__!=""}`)
	if err != nil {
		return err
	}
	for _, res := range results {
		fmt.Fprint(out, res.Metric["__name__"])
		fmt.Fprint(out, "{")
		for k, v := range res.Metric {
			if k == "__name__" {
				continue
			}
			fmt.Fprintf(out, `%s="%s",`, k, v)
		}
		fmt.Fprintf(out, "} ")
		for _, v := range res.Value {
			fmt.Fprintf(out, "%v ", v)
		}
		fmt.Fprintln(out)
	}
	return nil
}

func DumpTraces(out io.Writer, jaegerHostPort string) error {
	if !strings.HasPrefix(jaegerHostPort, "http") {
		jaegerHostPort = "http://" + jaegerHostPort
	}
	if _, err := fmt.Fprintf(out, "===== Dumping traces from %s ====\n", jaegerHostPort); err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	// get services
	res, err := http.Get(jaegerHostPort + "/api/services")
	if err != nil {
		return fmt.Errorf("getting services: %w", err)
	}
	svcs := jaeger.Services{}
	if err := json.NewDecoder(res.Body).Decode(&svcs); err != nil {
		return fmt.Errorf("decoding services: %w", err)
	}
	for _, svcName := range svcs.Data {
		fmt.Fprintf(out, "---- Service: %s ----\n", svcName)
		res, err := http.Get(jaegerHostPort + "/api/traces?service=" + svcName)
		if err != nil {
			fmt.Fprintln(out, "! ERROR getting trace:", err)
			continue
		}
		tq := jaeger.TracesQuery{}
		if err := json.NewDecoder(res.Body).Decode(&tq); err != nil {
			fmt.Fprintln(out, "! ERROR decoding trace:", err)
			continue
		}
		for _, trace := range tq.Data {
			if err := json.NewEncoder(out).Encode(trace); err != nil {
				fmt.Fprintln(out, "! ERROR encoding trace:", err)
			}
		}
	}
	return nil
}
