package exec

import (
	"strings"

	"github.com/prometheus/procfs"
)

func envStrsToMap(varsStr []string) map[string]string {
	vars := make(map[string]string, len(varsStr))

	for _, s := range varsStr {
		parts := strings.Split(s, "=")
		if len(parts) >= 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(strings.Join(parts[1:], "="))

			if key != "" && val != "" {
				vars[key] = val
			}
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

	return envStrsToMap(varsStr), nil
}
