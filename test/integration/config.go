package integration

import (
	"path"

	"github.com/grafana/beyla/test/tools"
)

var (
	pathRoot   = tools.ProjectDir()
	pathOutput = path.Join(pathRoot, "testoutput")
)
