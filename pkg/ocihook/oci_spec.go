package ocihook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const configJSONName = "config.json"

type Spec struct {
	Annotations map[string]string `json:"annotations,omitempty"`
	Process     *ProcessSpec      `json:"process,omitempty"`
	Mounts      []MountSpec       `json:"mounts,omitempty"`
}

type ProcessSpec struct {
	Env []string `json:"env,omitempty"`
}

type MountSpec struct {
	Destination string   `json:"destination,omitempty"`
	Source      string   `json:"source,omitempty"`
	Type        string   `json:"type,omitempty"`
	Options     []string `json:"options,omitempty"`
}

func LoadSpec(bundleDir string) (*Spec, error) {
	path := filepath.Join(bundleDir, configJSONName)
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read OCI spec %s: %w", path, err)
	}

	var spec Spec
	if err := json.Unmarshal(bytes, &spec); err != nil {
		return nil, fmt.Errorf("decode OCI spec %s: %w", path, err)
	}

	return &spec, nil
}

func SaveSpec(bundleDir string, spec *Spec) error {
	path := filepath.Join(bundleDir, configJSONName)
	bytes, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("encode OCI spec %s: %w", path, err)
	}
	bytes = append(bytes, '\n')

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, bytes, 0o600); err != nil {
		return fmt.Errorf("write temp OCI spec %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace OCI spec %s: %w", path, err)
	}

	return nil
}
