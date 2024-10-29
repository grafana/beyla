package k8s

import "path"

var (
	PathRoot            = path.Join("..", "..", "..", "..")
	PathOutput          = path.Join(PathRoot, "testoutput")
	PathKindLogs        = path.Join(PathOutput, "kind")
	PathIntegrationTest = path.Join(PathRoot, "test", "integration")
	PathComponents      = path.Join(PathIntegrationTest, "components")
	PathManifests       = path.Join(PathIntegrationTest, "k8s", "manifests")

	DockerfileTestServer       = path.Join(PathComponents, "testserver", "Dockerfile")
	DockerfileBeyla            = path.Join(PathComponents, "beyla", "Dockerfile")
	DockerfileBeylaK8sCache    = path.Join(PathComponents, "beyla-k8s-cache", "Dockerfile")
	DockerfilePinger           = path.Join(PathComponents, "grpcpinger", "Dockerfile")
	DockerfilePythonTestServer = path.Join(PathComponents, "pythonserver", "Dockerfile_8083")
	DockerfileHTTPPinger       = path.Join(PathComponents, "httppinger", "Dockerfile")

	PingerManifest               = path.Join(PathManifests, "/06-instrumented-client.template.yml")
	GrpcPingerManifest           = path.Join(PathManifests, "/06-instrumented-grpc-client.template.yml")
	UninstrumentedPingerManifest = path.Join(PathManifests, "/06-uninstrumented-client.template.yml")
	UninstrumentedAppManifest    = path.Join(PathManifests, "/05-uninstrumented-service.yml")
	PingerManifestProm           = path.Join(PathManifests, "/06-instrumented-client-prom.template.yml")
	GrpcPingerManifestProm       = path.Join(PathManifests, "/06-instrumented-grpc-client-prom.template.yml")
)

// Pinger stores the configuration data of a local pod that will be used to
// send recurring requests to the test server
type Pinger struct {
	PodName   string
	TargetURL string
}
