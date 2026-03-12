// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/internal/netolly/ebpf"
import "go.opentelemetry.io/obi/pkg/netolly/flowdef"

type portGuesser func(r *Record) uint16

func noGuess(_ *Record) uint16 { return 0 }

func serverPortOrdinalGuess(r *Record) uint16 {
	// assuming that ephemeral ports for clients would be usually higher
	return min(r.Id.DstPort, r.Id.SrcPort)
}

func clientPortOrdinalGuess(r *Record) uint16 {
	// assuming that ephemeral ports for clients would be usually higher
	return max(r.Id.DstPort, r.Id.SrcPort)
}

func serverPort(r *Record, guess portGuesser) uint16 {
	switch r.Metrics.Initiator {
	case InitiatorDst:
		return r.Id.SrcPort
	case InitiatorSrc:
		return r.Id.DstPort
	default:
		return guess(r)
	}
}

func clientPort(r *Record, guess portGuesser) uint16 {
	switch r.Metrics.Initiator {
	case InitiatorDst:
		return r.Id.DstPort
	case InitiatorSrc:
		return r.Id.SrcPort
	default:
		return guess(r)
	}
}

func (c *RecordGettersConfig) clientPortGuesser() portGuesser {
	switch c.PortGuessPolicy {
	case flowdef.PortGuessOrdinal:
		return clientPortOrdinalGuess
	case flowdef.PortGuessDisable:
		return noGuess
	default:
		return noGuess
	}
}

func (c *RecordGettersConfig) serverPortGuesser() portGuesser {
	switch c.PortGuessPolicy {
	case flowdef.PortGuessOrdinal:
		return serverPortOrdinalGuess
	case flowdef.PortGuessDisable:
		return noGuess
	default:
		return noGuess
	}
}
