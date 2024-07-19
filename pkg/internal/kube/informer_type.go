package kube

import (
	"strings"

	"github.com/grafana/beyla/pkg/internal/helpers/maps"
)

const (
	InformerService = maps.Bits(1 << iota)
	InformerReplicaSet
	InformerNode
)

func informerTypes(str []string) maps.Bits {
	return maps.MappedBits(
		str,
		map[string]maps.Bits{
			"service":     InformerService,
			"services":    InformerService,
			"replicaset":  InformerReplicaSet,
			"replicasets": InformerReplicaSet,
			"node":        InformerNode,
			"nodes":       InformerNode,
		},
		maps.WithTransform(strings.ToLower),
	)
}
