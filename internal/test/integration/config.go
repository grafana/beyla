package integration

import (
	"path"
	"time"

	"github.com/grafana/beyla/v3/internal/test/tools"
)

const (
	prometheusHostPort = "localhost:9090"
	testTimeout        = 60 * time.Second
)

var (
	pathRoot   = tools.ProjectDir()
	pathOutput = path.Join(pathRoot, "testoutput")
)
