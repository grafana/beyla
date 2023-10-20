package graph

import (
	"strings"
)

type dstConnector struct {
	demuxChan string // if empty, no demuxed channel but direct submission to the node
	dstNode   string
}

func allConnectorsFrom(in string) []dstConnector {
	var conns []dstConnector
	for _, connection := range strings.Split(in, ",") {
		conns = append(conns, connectorFrom(connection))
	}
	return conns
}

func connectorFrom(in string) dstConnector {
	parts := strings.Split(strings.TrimSpace(in), ":")
	if len(parts) == 1 {
		return dstConnector{
			dstNode: parts[0],
		}
	}
	return dstConnector{
		demuxChan: parts[0],
		dstNode:   parts[1],
	}
}
