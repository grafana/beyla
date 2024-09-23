package exec

import (
	"fmt"
	"strings"

	"github.com/prometheus/procfs"
)

func EnvVars(pid int32) (map[string]string, error) {
	proc, err := procfs.NewProc(int(pid))

	if err != nil {
		return nil, err
	}

	varsStr, err := proc.Environ()

	if err != nil {
		return nil, err
	}

	vars := make(map[string]string, len(varsStr))

	for _, s := range varsStr {
		parts := strings.Split(s, "=")
		if len(parts) == 2 {
			vars[parts[0]] = parts[1]
		}
	}

	fmt.Printf("%v\n", vars)

	return vars, nil
}
