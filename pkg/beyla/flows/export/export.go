package export

import (
	"encoding/json"
	"fmt"

	"github.com/grafana/beyla/pkg/internal/export/otel"
	"github.com/mariomac/pipes/pkg/node"
)

// TODO: put here any exporter configuration
type ExportConfig struct {
	Metrics *otel.MetricsConfig
}

func ExporterProvider(_ ExportConfig) (node.TerminalFunc[[]map[string]interface{}], error) {
	return func(in <-chan []map[string]interface{}) {
		for i := range in {
			// TODO: replace by something more useful
			bytes, _ := json.Marshal(i)
			fmt.Println(string(bytes))
		}
	}, nil
}
