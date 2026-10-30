package beyla

import (
	"bytes"
	"reflect"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/services"
)

// LoadRefreshConfig loads a configuration that refreshes the discovery criteria of a running
// Beyla. Unlike LoadConfig, it does not override the OBI process-wide settings again, as the
// running pipeline reads them concurrently and the startup load already set them.
//
// The environment variables are read from environment, a snapshot taken before the pipeline
// started: the OTLP exporters set some at runtime, which the startup load didn't see.
// A nil environment reads them from the process.
func LoadRefreshConfig(data []byte, environment map[string]string) (*Config, error) {
	cfg, err := loadConfigFile(bytes.NewReader(data), environment)
	if err != nil {
		return nil, err
	}

	if err := cfg.ValidateForRefresh(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) ChangedSettings(other *Config) []string {
	return changedFields("", reflect.ValueOf(c.withoutSelection()), reflect.ValueOf(other.withoutSelection()))
}

// changedFields descends into the struct fields that differ, to report the innermost ones.
func changedFields(path string, a, b reflect.Value) []string {
	if reflect.DeepEqual(a.Interface(), b.Interface()) {
		return nil
	}

	// The recursive checks here are convenience to report something decent back to Alloy
	if a.Kind() == reflect.Pointer && !a.IsNil() && !b.IsNil() {
		a, b = a.Elem(), b.Elem()
	}

	if a.Kind() != reflect.Struct {
		return []string{path}
	}

	var changed []string
	for i := range a.NumField() {
		field := a.Type().Field(i)
		if !field.IsExported() {
			continue
		}
		changed = append(changed, changedFields(fieldPath(path, field), a.Field(i), b.Field(i))...)
	}

	// The difference is in unexported fields, which only their struct can report.
	if len(changed) == 0 {
		return []string{path}
	}
	return changed
}

func fieldPath(parent string, field reflect.StructField) string {
	name, options, _ := strings.Cut(field.Tag.Get("yaml"), ",")
	switch {
	case options == "inline":
		return parent
	case name == "" || name == "-":
		name = field.Name
	}

	if parent == "" {
		return name
	}
	return parent + "." + name
}

func (c *Config) withoutSelection() Config {
	fixed := *c
	fixed.obi = nil
	fixed.Port = services.IntEnum{}
	fixed.TargetPIDs = services.IntEnum{}
	fixed.Exec = services.RegexpAttr{}
	fixed.AutoTargetExe = services.GlobAttr{}
	fixed.AutoTargetLanguage = services.GlobAttr{}
	fixed.Discovery.Instrument = nil
	fixed.Discovery.Services = nil
	fixed.Discovery.ExcludeInstrument = nil
	fixed.Discovery.ExcludeServices = nil
	fixed.Discovery.DefaultExcludeInstrument = nil
	fixed.Discovery.DefaultExcludeServices = nil
	return fixed
}
