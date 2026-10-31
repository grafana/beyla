package beyla

import "gopkg.in/yaml.v3"

// UnmarshalYAML exposes the Cohere opt-in that OBI's Config v1 YAML tags omit.
func (c *Config) UnmarshalYAML(node *yaml.Node) error {
	type plainConfig Config
	if err := node.Decode((*plainConfig)(c)); err != nil {
		return err
	}

	var extra struct {
		EBPF struct {
			PayloadExtraction struct {
				HTTP struct {
					GenAI struct {
						Cohere struct {
							Enabled *bool `yaml:"enabled"`
						} `yaml:"cohere"`
					} `yaml:"genai"`
				} `yaml:"http"`
			} `yaml:"payload_extraction"`
		} `yaml:"ebpf"`
	}
	if err := node.Decode(&extra); err != nil {
		return err
	}
	if enabled := extra.EBPF.PayloadExtraction.HTTP.GenAI.Cohere.Enabled; enabled != nil {
		c.EBPF.PayloadExtraction.HTTP.GenAI.Cohere.Enabled = *enabled
	}
	return nil
}
