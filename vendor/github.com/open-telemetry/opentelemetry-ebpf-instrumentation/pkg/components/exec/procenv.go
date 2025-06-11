package exec

import (
	"strings"

	"github.com/prometheus/procfs"
)

func envStrsToMap(varsStr []string) map[string]string {
	vars := make(map[string]string, len(varsStr))

	for _, s := range varsStr {
		keyVal := strings.SplitN(s, "=", 2)
		if len(keyVal) < 2 {
			continue
		}
		key := strings.TrimSpace(keyVal[0])
		val := strings.TrimSpace(keyVal[1])

		if key != "" && val != "" {
			vars[key] = val
		}
	}

	return vars
}

func EnvVars(pid int32) (map[string]string, error) {
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return nil, err
	}

	varsStr, err := proc.Environ()
	if err != nil {
		return nil, err
	}

	m := envStrsToMap(varsStr)

	return m, nil
}
