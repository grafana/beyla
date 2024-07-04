package kube

import "strings"

type InformerType int

const (
	InformerPod = InformerType(1 << iota)
	InformerService
	InformerReplicaSet
	InformerNode
)

func InformerTypes(str []string) InformerType {
	it := InformerType(0)
	for _, s := range str {
		switch strings.ToLower(s) {
		case "pod", "pods":
			it |= InformerPod
		case "service", "services":
			it |= InformerService
		case "replicaset", "replicasets":
			it |= InformerReplicaSet
		case "node", "nodes":
			it |= InformerNode
		}
	}
	return it
}

func (i InformerType) Has(it InformerType) bool {
	return i&it != 0
}
