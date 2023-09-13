package k8s

import "path"

var (
	PathRoot     = path.Join("..", "..", "..", "..")
	PathOutput   = path.Join(PathRoot, "testoutput")
	PathKindLogs = path.Join(PathOutput, "kind")
)

const (
	DockerfileTestServer = "../../components/testserver/Dockerfile"
	DockerfileBeyla = "../../components/beyla/Dockerfile"
	DockerfilePinger = "../../components/grpcpinger/Dockerfile"
)

// Pinger stores the configuration data of a local pod that will be used to
// send recurring requests to the test server
type Pinger struct {
	PodName      string
	TargetURL    string
	ConfigSuffix string
}
