package ocihook

import (
	"fmt"
	"slices"
	"strings"
)

type Decision struct {
	ShouldMutate bool
	Reason       string
}

func EvaluatePolicy(command string, spec *Spec, cfg Config) Decision {
	// Command-level gate keeps the mutation surface tight and explicit.
	if !slices.Contains(cfg.MutateCommands, command) {
		return Decision{ShouldMutate: false, Reason: fmt.Sprintf("command %q is not configured for mutation", command)}
	}

	if spec == nil {
		return Decision{ShouldMutate: false, Reason: "spec is missing"}
	}

	// Primary selector: annotation.
	// This mirrors the Kubernetes admission style and keeps mutation explicit.
	if key := strings.TrimSpace(cfg.Policy.OptInAnnotation); key != "" {
		value := ""
		if spec.Annotations != nil {
			value = strings.TrimSpace(spec.Annotations[key])
		}
		if isTruthy(value) {
			return Decision{ShouldMutate: true, Reason: "matched opt-in annotation"}
		}
	}

	// Fallback selector: environment variable inside OCI process env.
	// This is useful on plain Docker hosts where annotations may not be easy to set.
	if key := strings.TrimSpace(cfg.Policy.OptInEnvVar); key != "" {
		if processEnvHasTruthy(spec.Process, key) {
			return Decision{ShouldMutate: true, Reason: "matched opt-in env var"}
		}
	}

	return Decision{ShouldMutate: false, Reason: "no opt-in selector matched"}
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "1", "yes", "on", "enabled":
		return true
	default:
		return false
	}
}

func processEnvHasTruthy(process *ProcessSpec, key string) bool {
	if process == nil {
		return false
	}
	for _, entry := range process.Env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.TrimSpace(parts[0]) != key {
			continue
		}
		return isTruthy(parts[1])
	}
	return false
}
