.PHONY: proto compile

proto:
	protoc --go_out=. --go-grpc_out=. proto/service.proto

compile:
	go build -o bin/worker ./cmd/worker/main.go