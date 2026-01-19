//go:build integration

package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/mariomac/guara/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ti "go.opentelemetry.io/obi/pkg/test/integration"
)

const (
	serverURL     = "http://localhost:8381"
	smokeEndpoint = "/smoke"
	jsonEndpoint  = "/json_logger"

	containerImage = "hatest-testserver-logenricher"
)

func containerLogs(t require.TestingT, cl *client.Client, containerID string) []string {
	reader, err := cl.ContainerLogs(context.TODO(), containerID, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	require.NoError(t, err)
	defer reader.Close()

	var stdout, stderr strings.Builder
	_, err = stdcopy.StdCopy(&stdout, &stderr, reader)
	require.NoError(t, err)

	combined := stdout.String() + stderr.String()

	scanner := bufio.NewScanner(strings.NewReader(combined))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	require.NoError(t, scanner.Err())

	return lines
}

func testContainerID(t require.TestingT, cl *client.Client, image string) string {
	containers, err := cl.ContainerList(context.TODO(), container.ListOptions{All: true})
	require.NoError(t, err)

	for _, c := range containers {
		if c.Image == image {
			return c.ID
		}
	}

	return ""
}

func testLogEnricher(t *testing.T) {
	waitForTestComponentsNoMetrics(t, serverURL+smokeEndpoint)

	cl, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cl.Close()

	test.Eventually(t, testTimeout, func(t require.TestingT) {
		ti.DoHTTPGet(t, serverURL+jsonEndpoint, 200)

		containerID := testContainerID(t, cl, containerImage)
		require.NotEmpty(t, containerID, "could not find test container ID")
		logs := containerLogs(t, cl, containerID)
		require.NotEmpty(t, logs)

		var logIdx int
		// Loop from the end -- it might be possible that Beyla wasn't ready to inject
		// context when the test started, so get the latest request logs every time.
		for i := len(logs) - 1; i >= 0; i-- {
			if strings.Contains(logs[i], "span_id") {
				logIdx = i
				break
			}
		}

		var logFields map[string]string
		require.NoError(t, json.Unmarshal([]byte(logs[logIdx]), &logFields))

		assert.Equal(t, "this is a json log", logFields["message"])
		assert.Equal(t, "INFO", logFields["level"])
		assert.Contains(t, logFields, "trace_id")
		assert.Contains(t, logFields, "span_id")
	})
}
