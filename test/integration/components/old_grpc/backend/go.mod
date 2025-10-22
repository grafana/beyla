module github.com/mariomac/distributed-service-example/backend

go 1.20

require (
	github.com/caarlos0/env/v7 v7.1.0
	github.com/mariomac/distributed-service-example/worker v0.0.0
	google.golang.org/grpc v1.55.0
	google.golang.org/protobuf v1.30.0
)

require (
	github.com/golang/protobuf v1.5.3 // indirect
	golang.org/x/net v0.10.0 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	google.golang.org/genproto v0.0.0-20230306155012-7f2fa6fef1f4 // indirect
)

replace github.com/mariomac/distributed-service-example/worker v0.0.0 => ../worker
