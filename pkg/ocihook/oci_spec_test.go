package ocihook

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSpecRoundTrip_PreservesUnknownTopLevelAndProcessFields(t *testing.T) {
	bundle := t.TempDir()
	original := `{
  "ociVersion": "1.1.0",
  "annotations": {"beyla.grafana.com/inject":"true"},
  "process": {
    "cwd": "/",
    "args": ["/bin/sh", "-c", "echo hi"],
    "terminal": false,
    "env": ["PATH=/usr/bin", "BEYLA_INJECT=true"]
  },
  "linux": {"resources": {}},
  "mounts": []
}`
	if err := os.WriteFile(filepath.Join(bundle, "config.json"), []byte(original), 0o600); err != nil {
		t.Fatalf("write original config: %v", err)
	}

	spec, err := LoadSpec(bundle)
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}

	// mutate env to force save path
	spec.Process.Env = append(spec.Process.Env, "LD_PRELOAD=/__otel_sdk_auto_instrumentation__/injector/libotelinject.so")
	if err := SaveSpec(bundle, spec); err != nil {
		t.Fatalf("save spec: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("unmarshal saved config: %v", err)
	}

	if parsed["ociVersion"] == nil {
		t.Fatalf("expected ociVersion to be preserved")
	}
	if parsed["linux"] == nil {
		t.Fatalf("expected linux section to be preserved")
	}

	process, ok := parsed["process"].(map[string]any)
	if !ok {
		t.Fatalf("expected process object to be present")
	}
	if process["cwd"] != "/" {
		t.Fatalf("expected process.cwd to be preserved, got %#v", process["cwd"])
	}
	if _, ok := process["args"].([]any); !ok {
		t.Fatalf("expected process.args to be preserved")
	}
}
