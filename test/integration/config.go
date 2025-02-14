package integration

import (
	"path"

	"github.com/grafana/beyla/v2/test/tools"
)

var (
	pathRoot   = tools.ProjectDir()
	pathOutput = path.Join(pathRoot, "testoutput")
)
