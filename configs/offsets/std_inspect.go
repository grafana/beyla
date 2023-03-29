package main

import "net/http"

// This program is used to generate an executable that can be inspected by the go-offsets-tracker tool

func main() {
	http.ListenAndServe(":9090", http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// this doesn't need to have any sense!
		writer.WriteHeader(request.ProtoMajor)
	}))
}
