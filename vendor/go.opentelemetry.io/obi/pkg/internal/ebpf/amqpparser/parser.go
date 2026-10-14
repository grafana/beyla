// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amqpparser // import "go.opentelemetry.io/obi/pkg/internal/ebpf/amqpparser"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/internal/largebuf"
)

const maxFramesParsed = 128

var ErrNotAMQP = errors.New("not AMQP 1.0")

type Result struct {
	LooksLikeAMQP bool
	TransferCount int
}

type frameParseResult struct {
	descriptor descriptor
	found      bool
	stop       bool
}

type parserState struct {
	Result
	framesParsed int
}

// Parse parses an AMQP 1.0 payload from a LargeBufferReader and returns
// transfer facts for span creation.
func Parse(r *largebuf.LargeBufferReader) (Result, error) {
	if r.Remaining() < len(amqpMagic) {
		return Result{}, ErrNotAMQP
	}

	state := parserState{}
	for r.Remaining() > 0 {
		if startsWithMagic(r) {
			if _, err := parseProtocolHeader(r); err != nil {
				return state.resultOrError(err)
			}
			state.LooksLikeAMQP = true
			continue
		}

		if r.Remaining() < frameHeaderSize {
			if state.LooksLikeAMQP {
				break
			}
			return Result{}, ErrNotAMQP
		}

		frame, err := parseFrame(r, state.LooksLikeAMQP)
		if err != nil {
			return state.resultOrError(err)
		}
		if frame.found {
			state.LooksLikeAMQP = true
			if frame.descriptor == descriptorTransfer {
				state.TransferCount++
			}
		}
		if frame.stop {
			break
		}

		state.framesParsed++
		if state.framesParsed >= maxFramesParsed {
			break
		}
	}

	if state.LooksLikeAMQP {
		return state.Result, nil
	}
	return Result{}, ErrNotAMQP
}

func parseFrame(r *largebuf.LargeBufferReader, alreadyAMQP bool) (frameParseResult, error) {
	frameStart := r.ReadOffset()
	available := r.Remaining()
	header, err := parseFrameHeader(r)
	if errors.Is(err, errIncompleteFrame) {
		descriptor, found, derr := decodeBodyDescriptor(r, frameStart, available, header)
		if derr != nil && alreadyAMQP {
			return frameParseResult{}, derr
		}
		return frameParseResult{
			descriptor: descriptor,
			found:      found,
			stop:       true,
		}, nil
	}
	if err != nil {
		return frameParseResult{}, err
	}

	descriptor, found, err := parsePerformativeDescriptor(r, frameStart, header)
	if err != nil {
		return frameParseResult{}, err
	}
	return frameParseResult{
		descriptor: descriptor,
		found:      found,
	}, nil
}

func (s parserState) resultOrError(err error) (Result, error) {
	if s.LooksLikeAMQP {
		return s.Result, err
	}
	return Result{}, ErrNotAMQP
}

func decodeBodyDescriptor(r *largebuf.LargeBufferReader, frameStart, available int, header frameHeader) (descriptor, bool, error) {
	bodyStart := header.bodyOffset()
	if bodyStart >= available {
		return 0, false, nil
	}

	if err := skipToOffset(r, frameStart+bodyStart); err != nil {
		return 0, false, err
	}
	desc, found, err := parseDescriptor(r, header.Type, available-bodyStart)
	return desc, found, err
}

func skipToOffset(r *largebuf.LargeBufferReader, offset int) error {
	current := r.ReadOffset()
	if current >= offset {
		return nil
	}
	return r.Skip(offset - current)
}
