package k8s

import (
	"path"

	"github.com/grafana/beyla/v2/internal/test/integration/k8s/common/testpath"
)

var (
	DockerfileTestServer       = path.Join(testpath.Components, "testserver", "Dockerfile")
	DockerfileBeyla            = path.Join(testpath.Components, "beyla", "Dockerfile")
	DockerfileBeylaK8sCache    = path.Join(testpath.Components, "beyla-k8s-cache", "Dockerfile")
	DockerfilePinger           = path.Join(testpath.Components, "grpcpinger", "Dockerfile")
	DockerfilePythonTestServer = path.Join(testpath.Components, "pythonserver", "Dockerfile_7773")
	DockerfileHTTPPinger       = path.Join(testpath.Components, "httppinger", "Dockerfile")

	PingerManifest               = path.Join(testpath.Manifests, "/06-instrumented-client.template.yml")
	GrpcPingerManifest           = path.Join(testpath.Manifests, "/06-instrumented-grpc-client.template.yml")
	UninstrumentedPingerManifest = path.Join(testpath.Manifests, "/06-uninstrumented-client.template.yml")
	UninstrumentedAppManifest    = path.Join(testpath.Manifests, "/05-uninstrumented-service.yml")
	PingerManifestProm           = path.Join(testpath.Manifests, "/06-instrumented-client-prom.template.yml")
	GrpcPingerManifestProm       = path.Join(testpath.Manifests, "/06-instrumented-grpc-client-prom.template.yml")
)

// Pinger stores the configuration data of a local pod that will be used to
// send recurring requests to the test server
type Pinger struct {
	PodName   string
	TargetURL string
	Env       map[string]string
}
