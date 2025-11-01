package integration

import (
	"path"

	ti "go.opentelemetry.io/obi/pkg/test/integration"

	"github.com/grafana/beyla/v2/internal/test/tools"
)

var (
	pathRoot   = tools.ProjectDir()
	pathOutput = path.Join(pathRoot, "testoutput")
)

func testConfig() *ti.TestConfig {
	return &ti.TestConfig{
		EnvPrefix:          "BEYLA_",
		ComposeServiceName: "autoinstrumenter",
		ComposeImageName:   "hatest-autoinstrumenter",
		DockerfilePath:     "beyla/Dockerfile",
		ConfigPath:         "beyla-config.yml",
		MetricPrefix:       "beyla",
		IPAttribute:        "beyla.ip",
		SDKName:            "beyla",
		VersionPkg:         "buildinfo.Version",
	}
}
