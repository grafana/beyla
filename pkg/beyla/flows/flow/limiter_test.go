// Copyright Red Hat / IBM
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This implementation is a derivation of the code in
// https://github.com/netobserv/netobserv-ebpf-agent/tree/release-1.4

package flow

import (
	"strconv"
	"testing"

	"github.com/mariomac/pipes/pkg/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const limiterLen = 50

func TestCapacityLimiter_NoDrop(t *testing.T) {
	// GIVEN a limiter-enabled pipeline
	pipeIn, pipeOut := capacityLimiterPipe()

	// WHEN it buffers less elements than it's maximum capacity
	for i := 0; i < 33; i++ {
		pipeIn <- []*Record{{Interface: strconv.Itoa(i)}}
	}

	// THEN it is able to retrieve all the buffered elements
	for i := 0; i < 33; i++ {
		elem := <-pipeOut
		require.Len(t, elem, 1)
		assert.Equal(t, strconv.Itoa(i), elem[0].Interface)
	}

	// AND not a single extra element
	select {
	case elem := <-pipeOut:
		assert.Failf(t, "unexpected element", "%#v", elem)
	default:
		// ok!
	}
}

func TestCapacityLimiter_Drop(t *testing.T) {
	// GIVEN a limiter-enabled pipeline
	pipeIn, pipeOut := capacityLimiterPipe()

	// WHEN it receives more elements than its maximum capacity
	// (it's not blocking)
	for i := 0; i < limiterLen*2; i++ {
		pipeIn <- []*Record{{Interface: strconv.Itoa(i)}}
	}

	// THEN it is only able to retrieve all the nth first buffered elements
	// (plus the single element that is buffered in the output channel)
	for i := 0; i < limiterLen+1; i++ {
		elem := <-pipeOut
		require.Len(t, elem, 1)
		assert.Equal(t, strconv.Itoa(i), elem[0].Interface)
	}

	// BUT not a single extra element
	select {
	case elem := <-pipeOut:
		assert.Failf(t, "unexpected element", "%#v", elem)
	default:
		// ok!
	}
}

func capacityLimiterPipe() (in chan<- []*Record, out <-chan []*Record) {
	inCh, outCh := make(chan []*Record), make(chan []*Record)

	init := node.AsStart(func(initOut chan<- []*Record) {
		for i := range inCh {
			initOut <- i
		}
	})
	limiter := node.AsMiddle((&CapacityLimiter{}).Limit)
	term := node.AsTerminal(func(termIn <-chan []*Record) {
		for i := range termIn {
			outCh <- i
		}
	}, node.ChannelBufferLen(limiterLen))

	init.SendTo(limiter)
	limiter.SendTo(term)

	init.Start()

	return inCh, outCh
}
