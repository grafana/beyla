# Description

This test was adapted from [gRPC Basics: Go](https://grpc.io/docs/tutorials/basic/go.html),
please visit this website for more information.

The route guide server and client demonstrate how to use grpc go libraries to
perform unary, client streaming, server streaming and full duplex RPCs.

See the definition of the route guide service in `routeguide/route_guide.proto`.

# Run the sample code
To compile and run the server, assuming you are in the root of the `grpc`
folder, simply:

```sh
$ go run server/server.go
```

Likewise, to run the client:

```sh
$ go run client/client.go
```

# Optional command line flags
The server and client both take optional command line flags. For example, the
client and server run without TLS by default. To enable TLS:

```sh
$ go run server/server.go -tls=true
```

and

```sh
$ go run client/client.go -tls=true
```
