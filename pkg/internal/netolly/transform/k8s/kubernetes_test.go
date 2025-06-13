package k8s

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	attr "github.com/open-telemetry/opentelemetry-ebpf-instrumentation/pkg/export/attributes/names"
	"github.com/grafana/beyla/v2/pkg/internal/kube"
	"github.com/grafana/beyla/v2/pkg/internal/netolly/ebpf"
	"github.com/grafana/beyla/v2/pkg/kubecache/meta"
)

func TestTransform(t *testing.T) {
	var (
		defaultLogger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelWarn,
		}))
		defaultFlow = func() *ebpf.Record {
			return &ebpf.Record{
				NetFlowRecordT: ebpf.NetFlowRecordT{
					Id: ebpf.NetFlowId{},
				},
			}
		}
		defaultClusterName    = "test-beyla-cluster"
		defaultK8sClusterName = "test-beyla-k8s-cluster"

		notifier = meta.NewBaseNotifier(defaultLogger)
		store    = kube.NewStore(&notifier, kube.DefaultResourceLabels, nil)
	)

	type args struct {
		flow *ebpf.Record
	}

	testcases := []struct {
		name          string
		makeDecorator func() *decorator
		args          args
		checkFlow     func(flow *ebpf.Record, r *require.Assertions)
		expected      bool
	}{
		{
			name: "without cluster name",
			makeDecorator: func() *decorator {
				return &decorator{
					kube: store,
					log:  defaultLogger,
				}
			},
			args: args{
				flow: defaultFlow(),
			},
			checkFlow: func(_ *ebpf.Record, _ *require.Assertions) {},
			expected:  false,
		},
		{
			name: "with cluster name",
			makeDecorator: func() *decorator {
				return &decorator{
					kube:        store,
					log:         defaultLogger,
					clusterName: defaultClusterName,
				}
			},
			args: args{
				flow: defaultFlow(),
			},
			checkFlow: func(flow *ebpf.Record, r *require.Assertions) {
				r.Equal(map[attr.Name]string{
					attr.ClusterName:    defaultClusterName,
					attr.K8sClusterName: defaultClusterName,
				}, flow.Attrs.Metadata)
			},
			expected: false,
		},
		{
			name: "with k8s cluster name ",
			makeDecorator: func() *decorator {
				return &decorator{
					kube:        store,
					log:         defaultLogger,
					clusterName: defaultK8sClusterName,
				}
			},
			args: args{
				flow: defaultFlow(),
			},
			checkFlow: func(flow *ebpf.Record, r *require.Assertions) {
				r.Equal(map[attr.Name]string{
					attr.K8sClusterName: defaultK8sClusterName,
					attr.ClusterName:    defaultK8sClusterName,
				}, flow.Attrs.Metadata)
			},
			expected: false,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			decorator := tt.makeDecorator()

			r := require.New(t)

			actual := decorator.transform(tt.args.flow)
			r.Equal(tt.expected, actual)
			tt.checkFlow(tt.args.flow, r)
		})
	}
}
