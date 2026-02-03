package server

import (
	context "context"
	"errors"
	"math"
	"math/big"
	"math/rand/v2"

	"github.com/grafana/beyla/v3/internal/test/integration/components/old_grpc/worker/internal/gprc"
)

var one = big.NewInt(1)

type MultiplyServer struct {
	gprc.MultiplierServer
}

func (m *MultiplyServer) Loop(_ context.Context, request *gprc.LoopRequest) (*gprc.LoopResponse, error) {
	start := &big.Int{}
	start.SetBytes(request.From)
	if rand.Int64N(int64(math.Max(10.0, float64(start.Int64()/10)))) == 0 {
		return nil, errors.New("boom!")
	}
	result := (&big.Int{}).Set(start)
	end := &big.Int{}
	end.SetBytes(request.To)
	for start.Cmp(end) < 0 {
		start.Add(start, one)
		result.Mul(result, start)
	}
	return &gprc.LoopResponse{Result: result.Bytes()}, nil
}

func (m *MultiplyServer) mustEmbedUnimplementedMultiplierServer() {}
