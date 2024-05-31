package getters

import (
	"go.opentelemetry.io/otel/attribute"

	"github.com/grafana/beyla/pkg/internal/export/attributes"
	attr "github.com/grafana/beyla/pkg/internal/export/attributes/names"
	"github.com/grafana/beyla/pkg/internal/infraolly/process"
)

func procStatusOTELGettersUser(name attr.Name) (attributes.Getter[*process.Status, attribute.KeyValue], bool) {
	if name == attr.ProcCPUState {
		return func(_ *process.Status) attribute.KeyValue {
			return attribute.Key(attr.ProcCPUState).String("user")
		}, true
	}
	return procStatusOTELGetters(name)
}
func procStatusOTELGettersSystem(name attr.Name) (attributes.Getter[*process.Status, attribute.KeyValue], bool) {
	if name == attr.ProcCPUState {
		return func(_ *process.Status) attribute.KeyValue {
			return attribute.Key(attr.ProcCPUState).String("system")
		}, true
	}
	return procStatusOTELGetters(name)
}
func procStatusOTELGettersWait(name attr.Name) (attributes.Getter[*process.Status, attribute.KeyValue], bool) {
	if name == attr.ProcCPUState {
		return func(_ *process.Status) attribute.KeyValue {
			return attribute.Key(attr.ProcCPUState).String("wait")
		}, true
	}
	return procStatusOTELGetters(name)
}

// nolint:cyclop
func procStatusOTELGetters(name attr.Name) (attributes.Getter[*process.Status, attribute.KeyValue], bool) {
	var g attributes.Getter[*process.Status, attribute.KeyValue]
	switch name {
	case attr.ProcCommand:
		g = func(s *process.Status) attribute.KeyValue { return attribute.Key(attr.ProcCommand).String(s.Command) }
	case attr.ProcCommandLine:
		g = func(s *process.Status) attribute.KeyValue {
			return attribute.Key(attr.ProcCommand).String(s.CommandLine)
		}
	case attr.ProcOwner:
		g = func(s *process.Status) attribute.KeyValue { return attribute.Key(attr.ProcOwner).String(s.User) }
	case attr.ProcParentPid:
		g = func(s *process.Status) attribute.KeyValue {
			return attribute.Key(attr.ProcParentPid).Int(int(s.ParentProcessID))
		}
	case attr.ProcPid:
		g = func(s *process.Status) attribute.KeyValue {
			return attribute.Key(attr.ProcParentPid).Int(int(s.ProcessID))
		}
	}
	return g, g != nil
}
