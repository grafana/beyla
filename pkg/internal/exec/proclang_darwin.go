package exec

import (
	"debug/elf"

	"github.com/grafana/beyla/v2/pkg/internal/svc"
)

func FindProcLanguage(_ int32) svc.InstrumentableType {
	return svc.InstrumentableGeneric
}
