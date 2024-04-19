package rest

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	"google.golang.org/grpc/credentials/insecure"

	"github.com/mariomac/distributed-service-example/worker/pkg/gprc"
	"google.golang.org/grpc"
)

const (
	FactorialPath = "/factorial/"
)

var one = big.NewInt(1)

func FactorialService(workers []string, timeout time.Duration) http.HandlerFunc {
	var clients []gprc.MultiplierClient
	for _, workerAddr := range workers {
		conn, err := grpc.Dial(workerAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			log.Fatalf("can't connect to worker: %s", err)
		}
		clients = append(clients, gprc.NewMultiplierClient(conn))
	}
	maxWorkers := big.NewInt(int64(len(workers)))

	return func(rw http.ResponseWriter, req *http.Request) {
		inputStr := req.URL.Path[len(FactorialPath):]
		input := &big.Int{}
		input, ok := input.SetString(inputStr, 0)
		if !ok {
			rw.WriteHeader(http.StatusBadRequest)
			rw.Write([]byte(fmt.Sprintf("wrong input: %s\n", inputStr)))
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), timeout)
		defer cancel()
		var sliceLen *big.Int
		start := big.NewInt(1)
		actualWorkers := (&big.Int{}).Set(maxWorkers)
		if input.Cmp(actualWorkers) < 0 {
			actualWorkers.SetInt64(1)
			sliceLen = (&big.Int{}).Set(input)
		} else {
			sliceLen = (&big.Int{}).Div(input, maxWorkers)
		}
		end := (&big.Int{}).Set(sliceLen)
		awn := int(actualWorkers.Int64())
		resCh := make(chan *gprc.LoopResponse, awn)
		errsCh := make(chan error, awn)
		for i := 0; i < awn-1; i++ {
			sstart, send := (&big.Int{}).Set(start), (&big.Int{}).Set(end)
			log.Printf("sending to %s: (%s, %s)", workers[i], start.String(), end.String())
			go invokeWorker(ctx, clients[i], sstart, send, errsCh, resCh)
			start.Set(end).Add(start, one)
			end.Add(end, sliceLen)
		}
		log.Printf("sending to %s: (%s, %s)", workers[awn-1], start.String(), end.String())
		go invokeWorker(ctx, clients[awn-1], start, input, errsCh, resCh)

		result := big.NewInt(1)
		for i := 0; i < awn; i++ {
			select {
			case res := <-resCh:
				if res == nil || len(res.Result) == 0 {
					rw.WriteHeader(http.StatusInternalServerError)
					continue
				}
				ires := (&big.Int{}).SetBytes(res.Result)
				log.Printf("worker %d returned", i)
				result.Mul(result, ires)
			case err := <-errsCh:
				rw.WriteHeader(http.StatusInternalServerError)
				rw.Write([]byte(fmt.Sprintf("error calculating numbers: %s\n", err)))
				return
			case <-ctx.Done():
				rw.WriteHeader(http.StatusGatewayTimeout)
				return
			}
		}
		rw.Write([]byte(result.String()))
		rw.Write([]byte{'\n'})
	}
}

func invokeWorker(ctx context.Context, client gprc.MultiplierClient, start, end *big.Int, errsCh chan error, resCh chan *gprc.LoopResponse) {
	lr, err := client.Loop(ctx, &gprc.LoopRequest{From: start.Bytes(), To: end.Bytes()})
	if err != nil {
		errsCh <- err
	}
	resCh <- lr
}
