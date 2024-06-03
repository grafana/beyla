package process

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
)

// nolint:cyclop
func OTELGetters(name attr.Name) (attributes.Getter[*Status, attribute.KeyValue], bool) {
	var g attributes.Getter[*Status, attribute.KeyValue]
	switch name {
	case attr.ProcCommand:
		g = func(s *Status) attribute.KeyValue { return attribute.Key(attr.ProcCommand).String(s.Command) }
	case attr.ProcCommandLine:
		g = func(s *Status) attribute.KeyValue {
			return attribute.Key(attr.ProcCommand).String(s.CommandLine)
		}
	case attr.ProcOwner:
		g = func(s *Status) attribute.KeyValue { return attribute.Key(attr.ProcOwner).String(s.User) }
	case attr.ProcParentPid:
		g = func(s *Status) attribute.KeyValue {
			return attribute.Key(attr.ProcParentPid).Int(int(s.ParentProcessID))
		}
	case attr.ProcPid:
		g = func(s *Status) attribute.KeyValue {
			return attribute.Key(attr.ProcParentPid).Int(int(s.ProcessID))
		}
	}
	return g, g != nil
}
