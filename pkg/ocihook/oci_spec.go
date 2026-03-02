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
	extra       map[string]json.RawMessage
}

type ProcessSpec struct {
	Env   []string `json:"env,omitempty"`
	extra map[string]json.RawMessage
}

type MountSpec struct {
	Destination string   `json:"destination,omitempty"`
	Source      string   `json:"source,omitempty"`
	Type        string   `json:"type,omitempty"`
	Options     []string `json:"options,omitempty"`
}

func (s *Spec) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.extra = map[string]json.RawMessage{}
	for k, v := range raw {
		switch k {
		case "annotations":
			if err := json.Unmarshal(v, &s.Annotations); err != nil {
				return err
			}
		case "process":
			var p ProcessSpec
			if err := json.Unmarshal(v, &p); err != nil {
				return err
			}
			s.Process = &p
		case "mounts":
			if err := json.Unmarshal(v, &s.Mounts); err != nil {
				return err
			}
		default:
			s.extra[k] = v
		}
	}
	return nil
}

func (s Spec) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range s.extra {
		out[k] = v
	}
	if s.Annotations != nil {
		b, err := json.Marshal(s.Annotations)
		if err != nil {
			return nil, err
		}
		out["annotations"] = b
	}
	if s.Process != nil {
		b, err := json.Marshal(s.Process)
		if err != nil {
			return nil, err
		}
		out["process"] = b
	}
	if s.Mounts != nil {
		b, err := json.Marshal(s.Mounts)
		if err != nil {
			return nil, err
		}
		out["mounts"] = b
	}
	return json.Marshal(out)
}

func (p *ProcessSpec) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	p.extra = map[string]json.RawMessage{}
	for k, v := range raw {
		switch k {
		case "env":
			if err := json.Unmarshal(v, &p.Env); err != nil {
				return err
			}
		default:
			p.extra[k] = v
		}
	}
	return nil
}

func (p ProcessSpec) MarshalJSON() ([]byte, error) {
	out := map[string]json.RawMessage{}
	for k, v := range p.extra {
		out[k] = v
	}
	if p.Env != nil {
		b, err := json.Marshal(p.Env)
		if err != nil {
			return nil, err
		}
		out["env"] = b
	}
	return json.Marshal(out)
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
