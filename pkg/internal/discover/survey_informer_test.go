package discover

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/kube"
)

type recordingProcessMetadataResolver struct {
	calls      int
	nameAtCall string
}

func (r *recordingProcessMetadataResolver) ResolveMetadata(_ svc.InstrumentableType, fi *exec.FileInfo) {
	r.calls++
	r.nameAtCall = fi.ServiceAttrs().UID.Name
	fi.SetAutoServiceName("orders")
	fi.SetAutoServiceNamespace("shop")
	fi.SetMetadata(map[attr.Name]string{"service.version": "1.2.3"})
}

func TestSurveyFetchMetadataUsesProcessMetadataOutsideKubernetes(t *testing.T) {
	resolver := &recordingProcessMetadataResolver{}
	instrumentable := ebpf.Instrumentable{
		Type: svc.InstrumentableNodejs,
		FileInfo: exec.New(exec.Init{
			CmdExePath: "/usr/bin/node",
		}),
	}
	s := surveyor{processMetadataResolver: resolver}

	s.fetchMetadata(&instrumentable)

	assert.Equal(t, 1, resolver.calls)
	assert.Empty(t, resolver.nameAtCall, "process metadata must be resolved before the executable-name fallback")
	service := instrumentable.FileInfo.ServiceAttrs()
	assert.Equal(t, "orders", service.UID.Name)
	assert.Equal(t, "shop", service.UID.Namespace)
	assert.Equal(t, "1.2.3", service.Metadata["service.version"])
	assert.Equal(t, svc.InstrumentableNodejs, service.SDKLanguage)
}

func TestSurveyFetchMetadataKeepsKubernetesDecorationPath(t *testing.T) {
	resolver := &recordingProcessMetadataResolver{}
	instrumentable := ebpf.Instrumentable{
		Type: svc.InstrumentableNodejs,
		FileInfo: exec.New(exec.Init{
			CmdExePath: "/usr/bin/node",
		}),
	}
	s := surveyor{
		store:                   &kube.Store{},
		processMetadataResolver: resolver,
	}

	s.fetchMetadata(&instrumentable)

	assert.Zero(t, resolver.calls)
	assert.Equal(t, "node", instrumentable.FileInfo.ServiceAttrs().UID.Name)
}
