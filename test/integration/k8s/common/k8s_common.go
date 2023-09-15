package k8s

import "path"

var (
	PathRoot            = path.Join("..", "..", "..", "..")
	PathOutput          = path.Join(PathRoot, "testoutput")
	PathKindLogs        = path.Join(PathOutput, "kind")
	PathIntegrationTest = path.Join(PathRoot, "test", "integration")
	PathComponents      = path.Join(PathIntegrationTest, "components")
	PathManifests       = path.Join(PathIntegrationTest, "k8s", "manifests")

	DockerfileTestServer = path.Join(PathComponents, "testserver", "Dockerfile")
	DockerfileBeyla      = path.Join(PathComponents, "beyla", "Dockerfile")
	DockerfilePinger     = path.Join(PathComponents, "grpcpinger", "Dockerfile")

	PingerManifest     = path.Join(PathManifests, "/06-instrumented-client.template.yml")
	GrpcPingerManifest = path.Join(PathManifests, "/06-instrumented-grpc-client.template.yml")
)

// Pinger stores the configuration data of a local pod that will be used to
// send recurring requests to the test server
type Pinger struct {
	PodName   string
	TargetURL string
}
