package kube

import "strings"

type informerType int

const (
	InformerService = informerType(1 << iota)
	InformerReplicaSet
	InformerNode
)

func informerTypes(str []string) informerType {
	it := informerType(0)
	for _, s := range str {
		switch strings.ToLower(s) {
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

func (i informerType) Has(it informerType) bool {
	return i&it != 0
}
